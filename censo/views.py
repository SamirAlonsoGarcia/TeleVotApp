from django.http import HttpResponseRedirect, FileResponse, JsonResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.views import View
from django.conf import settings
from django.core.files.storage import default_storage
from django.core.mail import send_mail
from django.db import IntegrityError, connection, DatabaseError, transaction
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.urls import reverse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64
import os
import hashlib
import uuid
import json
import random
import math
import openpyxl # leer datos de excel
from .models import Noticias, Usuario, Censo, MesaElectoral, Votacion, Voto, Candidatura, Incidencia, CensoUsuario, CensoVotacion, CandidatosNombrados, InscritosVotacion, IntegrantesCandidatura, IntegrantesMesa, Certificado
from .forms import LoginForm, NuevoUsuarioForm, NuevaCandidaturaForm

#getobject_or_404 funcion que maneja la salida de una operacion con o sin parametros y que devuelve una pagina de error si no se puede procesar.
def es_admin(user):
    return user.is_staff or user.is_superuser

@login_required
@user_passes_test(es_admin)
def Administracion(request):
    incidencias = Incidencia.objects.exclude(IncidenciaSolucionada=True)
    form = NuevoUsuarioForm()
    censos = Censo.objects.all()
    votaciones = Votacion.objects.all()
    mesas_electorales = MesaElectoral.objects.all()
    return render(request, 'Administracion.html', {'incidencias': incidencias, 'form':form, 'form1':form,'censos': censos, 'votaciones': votaciones, 'mesasElectorales':mesas_electorales})

@login_required(login_url='tablonAnuncios')
def Inicio(request):
    userLogged = request.user
    Datos_usuario = {
        'nombre': userLogged.Nombre,
        'apellidos': userLogged.Apellidos,
        'documento_fiscal': userLogged.DocumentoFiscal,
        'coreo_electronico' : userLogged.email
    }

    incidenciasNoSolucionadas=Incidencia.objects.filter(IdUsuario=request.user,IncidenciaSolucionada=False)
    censos = Censo.objects.filter(censousuario__usuario=userLogged).distinct()
    inscritos = InscritosVotacion.objects.filter(usuario=userLogged)
    votaciones = Votacion.objects.filter(IdVotacion__in=[i.votacion.IdVotacion for i in inscritos])
    certi_usuario = Certificado.objects.filter(propietario_usuario=userLogged)
    if userLogged.primera_vez:
        return redirect('login')
    else:
        return render(request,'Inicio.html', {'usuario':Datos_usuario ,'incidenciasNoSolucionadas' : incidenciasNoSolucionadas, 'censos':censos, 'votaciones':votaciones , 'certificado':certi_usuario})

@login_required
def Censo_view(request):
    censos = Censo.objects.all()
    return render(request,'Censos.html', {'censos': censos})

@login_required
def Certificados(request):
    userLogged = request.user
    certificado_usuario = Certificado.objects.filter(propietario_usuario=userLogged)
    votaciones_inscrito_activo = InscritosVotacion.objects.filter(usuario=userLogged,votacion__Estado=True).values_list('votacion', flat=True)
    certificados_mesas = MesaElectoral.objects.filter(IdVotacion__in=votaciones_inscrito_activo, certificado__isnull=False)

    return render(request, 'Certificados.html', {'certificado':certificado_usuario, 'certificados_mesa':certificados_mesas})

@login_required
def Votacion_view(request):
    votaciones_activas = Votacion.objects.filter(Estado=True)
    votaciones_finalizadas = Votacion.objects.filter(Estado=False)
    return render(request, 'Votaciones.html', {'votaciones_activas': votaciones_activas, 'votaciones_finalizadas': votaciones_finalizadas})

@login_required
def Votacion_gestionar(request):
    if request.mode == 'POST':
        id_votacion = request.POST.get('votacion_id')
        accion = request.POST.get('accion')
        if not id_votacion:
            messages.error(request, "No Has seleccionado ninguna votacion")
            return redirect(Votacion_view)
        
        if accion == 'entrar':
            return redirect()

    return redirect(Votacion_view)

@login_required
def emitir_voto(request):
    if request.method == 'POST':
        votacion_id = request.POST.get('votacion_id')
        votacion= Votacion.objects.get(IdVotacion=votacion_id)
        #votacion = get_object_or_404(Votacion, pk=votacion_id)
        candid_votacion = CandidatosNombrados.objects.filter(votacion=votacion)
        candidaturas = Candidatura.objects.filter(
            IdCandidatura__in=candid_votacion.values_list('candidatura__IdCandidatura', flat=True)
        )

    return render(request, 'EmitirVotacion.html', {'votacion': votacion,'candidaturas': candidaturas})

#@login_required
#class EmitirVotoView(View):
#    def get(self, request, votacion_id):
#        votacion=Votacion.objects.get(IdVotacion=votacion_id)
#        candid_votacion = CandidatosNombrados.objects.filter(votacion=votacion)
#        candidaturas = Candidatura.objects.filter(
#            IdCandidatura__in=candid_votacion.values_list('candidatura__IdCandidatura', flat=True)
#        )
#        return render(request, 'EmitirVotacion.html' ,{'candidaturas': candidaturas,'votacion_id': votacion_id})
#
#    def post(self, request):
#        data = json.loads(request.body)
#        contenido = data.get('contenido')
#        firma = data.get('firma')

#        Voto.objects.create(
#            usuario=request.user,
#            contenido=contenido,
#            firma_digital=firma,
#        )

#        return JsonResponse({'status': 'ok'})

@login_required
def Noticia(request):
    noticias = Noticias.objects.all()
    return render(request, 'Noticias.html', {'noticias': noticias})

@login_required
def GuiaUsuario(request):
    return render(request, 'Guia_de_Usuario.html')

def tablonAnuncios(request):
    lista_noticias = Noticias.objects.all()
    form = LoginForm()

    return render(request, "Tablon_de_Anuncios.html", {'noticias': lista_noticias,'form': form,})

def login_view(request):
    form = LoginForm(request.POST or None)
    noticias = Noticias.objects.exclude(IdVotacionRelacionada=0)
    censos = Censo.objects.all()
    mesas = MesaElectoral.objects.all()
    votaciones = Votacion.objects.exclude(Estado=False)

    if request.method == 'POST' and form.is_valid():
        documento_fiscal = form.cleaned_data['documento_fiscal']
        password = form.cleaned_data['password']

        user = authenticate(request, username=documento_fiscal, password=password)

        if user is not None:
            login(request, user)
            return redirect('inicio')  
        else:
            messages.error(request, 'Documento Fiscal y/o contraseña incorrectos.')

    return render(request, 'Tablon_de_Anuncios.html', {'form': form , 'noticias': noticias, 'censos': censos, 'mesas': mesas, 'votaciones': votaciones})

@login_required
@user_passes_test(es_admin)
def subir_excel(request):
    if request.method == 'POST':
        try:
            excel_file = request.FILES['excel_file']
            file_path = default_storage.save(f'temp/{excel_file.name}', excel_file)
            nombre_censo = request.POST.get('nombre_censo')
            descripcion = request.POST.get('descripcion')

            wb = openpyxl.load_workbook(f'temp/{excel_file.name}', excel_file)
            ws=wb.active
            # Restamos 1 para omitir la cabecera
            total_censo= ws.max_row - 1

            nuevo_censo=Censo.objects.create(
                NombreCenso=nombre_censo,
                Descripcion=descripcion,
                nCensados=total_censo,
            )
            nuevo_censo.FicheroAsociado.save(excel_file.name, excel_file)
            nuevo_censo.save()
            wb.close()
            os.remove(default_storage.path(file_path))
            messages.success(request, f'Censo "{nombre_censo}" creado con éxito. Contenia:  {total_censo} censados.')
        except Exception as ex:
            print("Error al guardar el censo: ", ex.__traceback__)
        
    return render(request, 'Administracion.html')


def descargar_plantilla(request):
    file_path = os.path.join(settings.MEDIA_ROOT, 'Plantilla_Censos.xlsx')
    return FileResponse(open(file_path, 'rb'), as_attachment=True, filename='Plantilla_Censos.xlsx')

@login_required
def logout_view(request):
    logout(request)
    return redirect('login_view')

@login_required
def MandarIncidenciaCenso(request):

    if request.method=="POST" :
        id_censo = request.POST.get("censo_id")
        texto_alegacion= request.POST.get("Alegacion")
        archivo = request.FILES.get("file")
        titulo = request.POST.get("titulo")

        nueva_incidencia=Incidencia.objects.create(
            IdUsuario=request.user,
            IdVotacion= None,
            TituloIncidencia=titulo,
            IncidenciaSolucionada=False,
            TextoIncidencia=texto_alegacion,
            FicheroIncidencia=archivo
        )
        if id_censo:
            try:
                nueva_incidencia.IdCenso = Censo.objects.get(pk=id_censo)
                nueva_incidencia.save()
            except Censo.DoesNotExist:
                print("No has asociado la incidencia al censo correspondiente")

        return redirect('censos')
    
def crear_hash_unico(nombre,apellidos,dni):
    aleatorio = f"{nombre}{apellidos}{dni}{uuid.uuid4()}"
    return hashlib.sha256(aleatorio.encode()).hexdigest()
    
@login_required
@user_passes_test(es_admin)
def nuevo_usuario(request):
    if request.method == "POST" :
        form = NuevoUsuarioForm(request.POST)
        if form.is_valid():
            nombre_usuario = form.cleaned_data["Nombre"]
            apellidos_usuario = form.cleaned_data["Apellidos"]
            dni_usuario = form.cleaned_data["DocumentoFiscal"]
            email_usuario = form.cleaned_data["Email"]
            clave_encriptada = crear_hash_unico(nombre_usuario,apellidos_usuario,dni_usuario)
        try:
            FunUsuarioNuevo(nombre_usuario,apellidos_usuario,dni_usuario,email_usuario,clave_encriptada)
            messages.success(request, "Usuario Creado Correctamente")
        except IntegrityError as e:
            messages.error(request, "No se ha podido Insertar el usuario, ya esta creado en la BD")
        except Exception as ex:
            messages.error(request, f"No se ha podido Insertar el usuario, revisa los datos {str(ex)}")
            return redirect('administracion')
    else:
        form=NuevoUsuarioForm()
        
    return render(request, 'Administracion.html', {'form': form})

def FunUsuarioNuevo(nombreUsuario, apellidosUsuario, Dni, email, claveUser):
    usuario_nuevo = Usuario.objects.create(
        Nombre=nombreUsuario,
        Apellidos=apellidosUsuario,
        DocumentoFiscal = Dni,
        email=email,
        username=Dni,
        IdEncriptado=claveUser
    )
    usuario_nuevo.save()
    return usuario_nuevo

@transaction.atomic
@login_required
@user_passes_test(es_admin)
def inscribir_usuarios_censo(request):
    if request.method == "POST" :
        censo_id = request.POST.get("censo_id")

        if not censo_id:
            messages.error(request,"NO has seleccionado ninguno censo")
            return redirect('administracion')

        censo = Censo.objects.get(IdCenso=censo_id)

        fichero_ruta = censo.FicheroAsociado.path
        wb = openpyxl.load_workbook(fichero_ruta)
        hoja = wb.active

    for fila in hoja.iter_rows(min_row=2, values_only=True):
        if not fila or not fila[0]:
            continue
        Dni = fila[0]
        nombre = fila[1]
        apellidos = fila[2]
        email = fila[3]
        clave_encriptada = crear_hash_unico(nombre, apellidos, Dni)

        usuario, creado = Usuario.objects.get_or_create(
            username=Dni,
            defaults={
                'Nombre': nombre,
                'Apellidos': apellidos,
                'DocumentoFiscal': Dni,
                'email': email,
                'IdEncriptado': clave_encriptada,
            }
        )

        if creado:
            messages.success(request, f"Usuario Creado: {Dni}")
        else:
            messages.error(request, f"Usuario ya existente: {Dni}")

        _, relacion = CensoUsuario.objects.get_or_create(
            usuario=usuario,
            censo=censo
        )

        if relacion:
            messages.success(request,"Insertado el usuario: {Dni} en el censo.")
        else:
            messages.error(request,"El usuario ya estaba inscrito en el censo correspondiente")

    return render(request, 'Administracion.html')

@login_required
@user_passes_test(es_admin)
def gestionar_votaciones(request):
    votacion_id = request.POST.get("votacion_id") or request.GET.get("votacion_id")
    if votacion_id:
        votacion = Votacion.objects.get(IdVotacion=votacion_id)
        censos = Censo.objects.all()
        form1 = NuevaCandidaturaForm()
        mesa_ya_sorteada = MesaElectoral.objects.filter(IdVotacion=votacion).exists()
        candidaturas_votacion = Candidatura.objects.filter(candidatosnombrados__votacion=votacion)
        integrantes_asociados={}
        for candidatura in candidaturas_votacion:
            integrantes = IntegrantesCandidatura.objects.filter(candidatura=candidatura).select_related('usuario')
            integrantes_asociados[candidatura.IdCandidatura] = [integra.usuario.username for integra in integrantes]
        return render(request, "ManejarVotacion.html", {'form1': form1,'censos': censos,'votacion': votacion,'mesa_ya_sorteada': mesa_ya_sorteada, 'candidaturas':candidaturas_votacion, 'integrantes':integrantes_asociados})
    
    messages.error("No has seleccionado ninguna votacion")
    return redirect('administracion')

def asignar_censo_votacion(request):
    if request.method == "POST":
        censo_id = request.POST.get("censo_id")
        votacion_id = request.POST.get("votacion_id")

        if not censo_id or not votacion_id:
            messages.error(request, "No has seleccionado ningún censo o votación.")
            return HttpResponseRedirect(f"{reverse('gestionar_votaciones')}?votacion_id={votacion_id}")
        else:
            censo = Censo.objects.get(IdCenso=censo_id)
            votacion = Votacion.objects.get(IdVotacion=votacion_id)

            __, creado = CensoVotacion.objects.get_or_create(
                censo=censo,
                votacion=votacion
            )

            if creado:
                messages.success(request, f"Se asignó el censo {censo.NombreCenso} a la votación {votacion.TituloVotacion}.")
                return HttpResponseRedirect(f"{reverse('gestionar_votaciones')}?votacion_id={votacion_id}")
            else:
                messages.error(request, f"Ya estaba asociado el censo {censo.NombreCenso} a la votación {votacion.TituloVotacion}.")
                return HttpResponseRedirect(f"{reverse('gestionar_votaciones')}?votacion_id={votacion_id}")

    return HttpResponseRedirect(f"{reverse('gestionar_votaciones')}?votacion_id={votacion_id}")

@login_required
@user_passes_test(es_admin)
def crear_candidatura(request):
    if request.method == "POST":        
        form = NuevaCandidaturaForm(request.POST)
        votacion_id = request.POST.get("votacion_id")
        votacionSel = Votacion.objects.get(IdVotacion=votacion_id)
        if form.is_valid():
            candidatura_nueva=form.save(commit=False)
            candidatura_nueva.save()
            for usuario in form.cleaned_data['usuarios']:
                IntegrantesCandidatura.objects.create(candidatura=candidatura_nueva, usuario=usuario)
            CandidatosNombrados.objects.get_or_create(votacion=votacionSel,candidatura=candidatura_nueva)
            messages.success(request,"Se creo la nueva candidatura correctamente")
            return HttpResponseRedirect(f"{reverse('gestionar_votaciones')}?votacion_id={votacion_id}")
    return HttpResponseRedirect(f"{reverse('gestionar_votaciones')}?votacion_id={votacion_id}")
@login_required
@user_passes_test(es_admin)
def asignar_usuarios_votacion(request):
    if request.method == "POST":
        votacion_id = request.POST.get("votacion_id")
        votacionSel = Votacion.objects.get(IdVotacion=votacion_id)
        votacionCenso=CensoVotacion.objects.get(votacion=votacionSel)
        censo = votacionCenso.censo
        usuariosCenso=CensoUsuario.objects.filter(censo=censo)
        if usuariosCenso.exists():
            for user in usuariosCenso:
                InscritosVotacion.objects.get_or_create(votacion=votacionSel, usuario=user.usuario)
            messages.success(request,"Se ha incluido los usuarios del censo asociado a la votacion")
        else:
            messages.error(request,"No esta asociado el censo todavia a la votacion")
    return HttpResponseRedirect(f"{reverse('gestionar_votaciones')}?votacion_id={votacion_id}")


@login_required
@user_passes_test(es_admin)
def notificar_usuarios_votacion(request):
    if request.method == "POST":  
        votacion_id = request.POST.get("votacion_id")
        votacionSel = Votacion.objects.get(IdVotacion=votacion_id)
        
        try:
            votacionCenso = CensoVotacion.objects.get(votacion=votacionSel)
        except CensoVotacion.DoesNotExist:
            messages.error(request, "No está asociado ningún censo a esta votación.")
            return HttpResponseRedirect(f"{reverse('gestionar_votaciones')}?votacion_id={votacion_id}")

        censo = votacionCenso.censo
        usuariosCenso = CensoUsuario.objects.filter(censo=censo)
        errores = []
        for user in usuariosCenso:
            exito = enviarNotificacionUsuario(user, votacionSel)
            if not exito:
                # usuario que no ha sido notificado.
                errores.append(str(user))  

        if errores:
            messages.error(request,f"Algunos correos no se pudieron enviar: {', '.join(errores)}")
        else:
            messages.success(request, "Se notificó correctamente a todos los usuarios.")

    return HttpResponseRedirect(f"{reverse('gestionar_votaciones')}?votacion_id={votacion_id}")

@login_required
@user_passes_test(es_admin)
def enviarNotificacionUsuario(usuario, votacion):
    try:
        user_sel = usuario.usuario
        votacion_sel = votacion

        email_usuario = user_sel.email
        asunto = f"Inscripción a la votación: {votacion_sel.TituloVotacion}"
        mensaje = (
            f"Hola {user_sel.Nombre}, {user_sel.Apellidos}\n\n"
            f"Te informamos que has sido inscrito/a correctamente en la votación:\n"
            f"Título: {votacion_sel.TituloVotacion}\n"
            f"Descripción: {votacion_sel.Descripcion}\n\n"
            f"Gracias por participar.\n\n"
            f"Este es un mensaje automático, por favor no respondas."
        )

        send_mail(
            subject=asunto,
            message=mensaje,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email_usuario],
            fail_silently=False
            )
        return True
    except Exception as e:
        print(f"Error al enviar correo: {e}")
        return False
    
@login_required
@user_passes_test(es_admin)
def sortear_mesa(request):
    #obtenemos la info de que votacion es
    votacion_id = request.POST.get("votacion_id")
    votacion=Votacion.objects.get(IdVotacion=votacion_id)
    #comprobamos que la mesa no exista, que este sorteada
    mesa_ya_sorteada= MesaElectoral.objects.filter(IdVotacion=votacion_id)
    if not mesa_ya_sorteada and request.method == "POST":
        censo_votacion = CensoVotacion.objects.get(votacion=votacion)
        if not censo_votacion:
            messages.error(request, f"La votacion {votacion.TituloVotacion} no tiene un censo asociado. Asocia primero el censo a la votacion, crea la/s candidaturas y despues repite el proceso")
            return HttpResponseRedirect(f"{reverse('gestionar_votaciones')}?votacion_id={votacion_id}")
        else:
            # Obtenemos si hay candidatura asociada a la votacion, y si no la hay no continuamos el proceso
            candidaturas = CandidatosNombrados.objects.filter(votacion=votacion).values_list('candidatura', flat=True)
            if not candidaturas:
                messages.error(request,f"La Votacion {votacion.TituloVotacion} no tiene ninguna candidatura creada. Crea primero la candidatura ya que los candidatos no son seleccionables para la mesa.")
                return HttpResponseRedirect(f"{reverse('gestionar_votaciones')}?votacion_id={votacion_id}")
            else:
                usuarios_candidatos_ids = set()
                for candidatura_id in candidaturas:
                    usuarios = IntegrantesCandidatura.objects.filter(candidatura=candidatura_id).values_list('usuario', flat=True)
                    usuarios_candidatos_ids.update(usuarios)

                usuarios_censo_ids = CensoUsuario.objects.filter(censo=censo_votacion.censo).values_list('usuario', flat=True)
                usuarios_elegibles = Usuario.objects.filter(id__in=usuarios_censo_ids).exclude(id__in=usuarios_candidatos_ids)

                # 1 mesa por cada 25 personas (redondeado hacia arriba)
                total_usuarios = usuarios_elegibles.count()
                n_componentes_mesa = math.ceil(total_usuarios / 25)

                usuarios_seleccionados = random.sample(list(usuarios_elegibles), n_componentes_mesa)
                nueva_mesa=MesaElectoral.objects.create(IdVotacion=votacion,NombreMesa=f"{votacion.TituloVotacion}" + " " + "Mesa Electoral 1",Sorteada=True)
                for us in usuarios_seleccionados:
                    IntegrantesMesa.objects.create(usuario=us,mesa=nueva_mesa)

                messages.success(request, "Se han creado y sorteado las mesas necesarias. Queda pendiente la asignacion de los certificados de cada")
                return HttpResponseRedirect(f"{reverse('gestionar_votaciones')}?votacion_id={votacion_id}")
    else:
        messages.error(request, f"La mesa/s electoral/es de esta votacion: {votacion.TituloVotacion}  ya esta creada/s.")
        return HttpResponseRedirect(f"{reverse('gestionar_votaciones')}?votacion_id={votacion_id}")

@login_required
@user_passes_test(es_admin)    
def eliminar_candidaturas(request):
    votacion_id = request.POST.get("votacion_id")
    candidatura_id = request.POST.get("candidatura_id")
    candidatura = Candidatura.objects.get(IdCandidatura=candidatura_id)
    if candidatura:
        Candidatura.objects.delete(candidatura)
    else:
        messages.error("No has seleccionado ninguna candidatura para eliminar")
        return HttpResponseRedirect(request,f"{reverse('gestionar_votaciones')}?votacion_id={votacion_id}")


@login_required
@user_passes_test(es_admin)
def asignar_certificado_mesa(request):
    mesa_electoral_id = request.POST.get("mesa_id")
    mesa_electoral=MesaElectoral.objects.get(IdMesa=mesa_electoral_id)
    if mesa_electoral:
        clave_privada = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        clave_privada_encriptada = clave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        clave_publica_encriptada = clave_privada.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        Certificado.objects.create(
            TipoCertificado='mesa',
            clave_publica=clave_publica_encriptada,
            clave_privada=clave_privada_encriptada,
            propietario_mesa = mesa_electoral
        )
        messages.success("Se ha asignado el certificado a la mesa electoral")
        return redirect(request,'administracion')
    else:
        messages.error("No has seleccionado ninguna Mesa Electoral")
        return redirect(request,'administracion')
    
@login_required
def crear_certificado_personal(request):
    userLogged = request.user
    existe_certificado = Certificado.objects.filter(propietario_usuario=userLogged)
    if not existe_certificado:
        clave_privada = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        clave_privada_encriptada = clave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        clave_publica_encriptada = clave_privada.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        Certificado.objects.create(
            TipoCertificado='usuario',
            clave_publica=clave_publica_encriptada,
            clave_privada=clave_privada_encriptada,
            propietario_usuario = userLogged
        )
        messages.success(request,f"Se ha asignado un certificado propio de la aplicacion al usuario {userLogged.DocumentoFiscal}")
    else:
        messages.error(request,f"El usuario: {userLogged.DocumentoFiscal}, ya tiene un certificado asignado. No es posible volver a crearlo")

    return redirect('certificados')

def cambiar_contraseña(request):
    return render(request, 'CambiarContraseña.html')

def modificar_contraseña(request):
    if request.method =="POST":
        usuario_id = request.POST.get('usuario_id')
        user = Usuario.objects.get(DocumentoFiscal=usuario_id)
        antigua_contraseña = request.POST.get('antigua_contraseña')
        nueva_contraseña = request.POST.get('nueva_contraseña')
        confir_contraseña = request.POST.get('confirmar_contraseña')
        if user:
            if request.user.check_password(antigua_contraseña):
                messages.error("La contraseña anterior no es la correcta, por favor prueba otra vez")
                return redirect(request,'cambiar_contraseña')

            if nueva_contraseña != confir_contraseña :
                messages.error("No has introducido la misma nueva contraseña. Vuelve a intentarlo y asegurate que sean la misma.")
                return redirect(request,'cambiar_contraseña')
            
            user.set_password(nueva_contraseña)
            user.primera_vez=False
            user.save()

            messages.success(request,f"Se modifico correctamente la contraseña del usuario: {user.DocumentoFiscal}")
            return redirect('login')
        else:
            messages.error(request,"El usuario introducio no existe. Por favor revisa que el usuario sea correcto")
        

    return redirect('login')

def volverInicio(request):
    return redirect('login')

def certificar_voto(request):
    if request.method == "POST":
        usuario = request.user
        candidatura_id = request.POST.get("candidatura_id")
        candidatura = Candidatura.objects.get(IdCandidatura=candidatura_id)
        candidatura_votacion=CandidatosNombrados.objects.get(candidatura=candidatura)
        votacion = Votacion.objects.get(IdVotacion=candidatura_votacion.votacion.IdVotacion)

        voto_creado=Voto.objects.filter(IdVotacion=votacion, idUsuario=usuario)

        if not voto_creado:
            claves_firma=obtenerCertificados(usuario, votacion.IdVotacion)

            voto_cont = f"{candidatura_votacion.votacion.IdVotacion}|{candidatura_votacion.candidatura.IdCandidatura}"

            voto_cifrado= cifrar_clave_publica(voto_cont, claves_firma["cla_mesa_publica"])
            voto_cif_usua= cifrar_con_clave_privada(voto_cont, claves_firma["cla_usuario_privado"])

            Voto.objects.create(
                IdVotacion=votacion,
                idUsuario=usuario,
                hashVoto=voto_cifrado + " :: " + voto_cif_usua
            )
            messages.success(request,"SU VOTO SE EMITIÓ CORRECTAMENTE")
        else:
            messages.success(request,"YA HAS VOTADO EN LA VOTACION ACTUAL, NO ES POSSIBLE VOLVER A VOTAR")
    return redirect('votaciones')

def obtenerCertificados(usuario, votacion_id):
    cert_usuario = Certificado.objects.get(propietario_usuario=usuario)
    mesaVot = MesaElectoral.objects.get(IdVotacion=votacion_id)
    cert_mesa = Certificado.objects.get(propietario_mesa=mesaVot)
    return({"cla_usuario_privado":cert_usuario.clave_privada, "cla_mesa_publica":cert_mesa.clave_publica})

def cifrar_clave_publica(contenido, clave_publica):
    clave_pub = serialization.load_pem_public_key(clave_publica.encode(),backend=default_backend())
    bytes_mensaje = contenido.encode()
    contenido_cifrado= clave_pub.encrypt(
        bytes_mensaje,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(contenido_cifrado).decode()

def descifrar_clave_publica(contenido, firma ,clave_publica):
    clave_pub = serialization.load_pem_public_key(
        clave_publica.encode(),
        backend=default_backend()
    )
    val_firma = base64.b64decode(firma.encode())

    try:
        clave_pub.verify(
            val_firma,
            contenido.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    except:
        return 0

def cifrar_con_clave_privada(contenido, clave_privada):
    clave_priv = serialization.load_pem_private_key(
        clave_privada.encode(),
        password=None,
        backend=default_backend()
    )
    mensaje_firmado=clave_priv.sign(
        contenido.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    return base64.b64encode(mensaje_firmado).decode()

def descifrar_con_clave_privada(contenido_cifrado_base64, clave_privada):
    clave_priv = serialization.load_pem_private_key(
        clave_privada.encode(),
        password=None,
        backend=default_backend()
    )

    contenido_cifrado = base64.b64decode(contenido_cifrado_base64.encode())

    contenido_descifrado = clave_priv.decrypt(
        contenido_cifrado,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256),
            algorithm=hashes.SHA256,
            label=None
        )
    )

    return contenido_descifrado.decode()

@login_required
def estadisticasVotacion(request):
    votacion_id=request.POST.get("votacion_id")
    votacion=Votacion.objects.get(IdVotacion=votacion_id)
    #votacion = get_object_or_404(Votacion, IdVotacion=votacion_id)
    
    total_esperado = votacion.NParticipantes
    total_emitidos = Voto.objects.filter(IdVotacion=votacion).count()

    participacion = (total_emitidos / total_esperado) * 100 if total_esperado else 0

    # Confirmación de voto (usuario ha votado)
    ya_votado = Voto.objects.filter(IdVotacion=votacion, idUsuario=request.user).exists()

    return render(request, 'EstadisticasVotacion.html', {'votacion': votacion,'total_esperado': total_esperado,'total_emitidos': total_emitidos,'participacion': participacion,'ya_votado': ya_votado})

@login_required
def recuentoVotacion(request):
    votacion_id=request.POST.get("votacion_id")
    votacion = Votacion.objects.get(IdVotacion=votacion_id)

    # Verifica que el usuario es miembro de la mesa para esa votación
    es_miembro_mesa = MesaElectoral.objects.filter(votacion=votacion, usuario=request.user).exists()

    if not es_miembro_mesa:
        return HttpResponseForbidden("No tienes permiso para autorizar el recuento.")

    # Cambiar el estado de la votación
    if votacion.estado == False:
        votacion.RecuentoAutorizado = True
        votacion.save()
        messages.success(request, "Se ha autorizado el recuento.")
        mesa_nombra = MesaElectoral.objects.get(votacion=votacion)
        certificados = Certificado.objects.get(propietario_mesa=mesa_nombra)
        return render(request, 'RecuentoVotacion.Html', {'certificados':certificados, 'votacion':votacion})
    else:
        messages.warning(request, "La votación aún no está cerrada o ya se autorizó el recuento.")
        return redirect(request,'votaciones')

@login_required
def Incidencias(request):
    return redirect('votaciones')