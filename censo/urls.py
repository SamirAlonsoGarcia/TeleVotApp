from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth.views import LogoutView
from . import views

urlpatterns=[
    path('', views.login_view, name='login'),
    path('seleccionar-rol/', views.seleccionar_rol, name='seleccionar_rol'),
    # Dividimos urls por roles para mantenimiento
    #admin. El domino/admin esta reservado para el admin de django
    path('inicio/admin/', views.Inicio_admin, name='Inicio_admin'),
    path('inicio/admin/crear-usuario/', views.admin_crear_usuario, name='Admin_crear_usuario'),
    path('inicio/admin/usuarios/', views.admin_gestion_usuarios, name='Admin_gestion_usuarios'),
    #junta electoral
    path('inicio/junta/', views.Inicio_junta, name='Inicio_junta'),
    #censo
    path('junta/censos/', views.Censos_junta, name='Junta_censos'),
    path('junta/censos/subir/', views.junta_censo_subir_excel, name='Junta_censo_subir_excel'),
    path('junta/censos/inscribir/', views.junta_censo_inscribir_usuarios, name='Junta_censo_inscribir'),
    #votacion
    path('junta/votaciones/', views.junta_votaciones_listado, name='Junta_votaciones_listado'),
    path('junta/votaciones/gestionar/', views.junta_votaciones_gestionar, name='Junta_votaciones_gestionar'),
    path('junta/votaciones/asignar-censo/', views.junta_vot_asignar_censo, name='Junta_vot_asignar_censo'),
    path('junta/votaciones/inscribir-usuarios/', views.junta_vot_inscribir_usuarios, name='Junta_vot_inscribir_usuarios'),
    path('junta/votaciones/crear-candidatura/', views.junta_vot_crear_candidatura, name='Junta_vot_crear_candidatura'),
    path('junta/votaciones/notificar/', views.junta_vot_notificar_usuarios, name='Junta_vot_notificar'),
    path('junta/votaciones/sortear-mesa/', views.junta_vot_sortear_mesa, name='Junta_vot_sortear_mesa'),
    path('junta/votaciones/eliminar-candidatura/', views.junta_vot_eliminar_candidatura, name='Junta_vot_eliminar_candidatura'),
    #incidencias y noticias
    path('junta/incidencias/', views.junta_incidencias, name='Junta_incidencias'),
    path('junta/noticias/', views.junta_noticias, name='Junta_noticias'),
    #mesa electoral
    path('inicio/mesa/', views.Inicio_mesa, name='Inicio_mesa'),
    path('mesa/certificado/', views.mesa_certificado, name='Mesa_certificado'),
    path('mesa/recuento/', views.mesa_recuento, name='Mesa_recuento'),
    path('mesa/noticias/', views.mesa_noticias, name='Mesa_noticias'),
    path('mesa/incidencias/', views.mesa_incidencias, name='Mesa_incidencias'),
    #director campaña
    path('inicio/director/', views.Inicio_director, name='Inicio_director'),
    #votante
    # elector
    path('inicio/elector/', views.Inicio_votante, name='Inicio_votante'),

    # menú principal del elector
    path('elector/votaciones/', views.Votacion_view, name='Elector_votaciones'),
    path('elector/censos/', views.Censo_view, name='Elector_censos'),
    path('elector/certificados/', views.Certificados, name='Elector_certificados'),
    path('elector/noticias/', views.Noticia, name='Elector_noticias'),

    # acciones sobre votaciones
    path('elector/votaciones/emitir/', views.emitir_voto, name='Elector_emitir_voto'),
    path('elector/votaciones/estadisticas/', views.estadisticasVotacion, name='Elector_estadisticas'),

    # incidencias y censo
    path('elector/censos/incidencia/', views.MandarIncidenciaCenso, name='Elector_incidencia_censo'),
    path('elector/incidencias/', views.elector_incidencias, name='Elector_incidencias'),
    path('elector/votaciones/incidencia/', views.MandarIncidenciaVotacion, name='Elector_incidencia_votacion'),

    # certificados personales
    path('elector/certificados/crear/', views.crear_certificado_personal, name='Elector_crear_certificado'),
    path('elector/votaciones/certificar-voto/', views.certificar_voto, name='Elector_certificar_voto'),
    # guia de usuario para tqodos los roles, va en el footer
    path('guia-usuario/', views.GuiaUsuario, name='Guia_usuario_global'),


    #antiguas
    path('admin/', views.Inicio_admin, name='dashboard_admin'),
    path('mesa/', views.Inicio_mesa, name='dashboard_mesa'),
    path('votante/', views.Inicio_votante, name='dashboard_votante'),
    path('director/', views.Inicio_director, name='dashboard_director'),
    path('junta/', views.Inicio_junta, name='dashboard_junta'),
    #path('Inicio/', views.Inicio, name='inicio'),
    path('Censo/', views.Censo_view, name='censos'),
    path('Certificados/', views.Certificados, name='certificados'),
    path('Votaciones/', views.Votacion_view, name='votaciones'),
    path('Noticias/', views.Noticia, name='noticias'),
    path('Guia_de_Usuario/', views.GuiaUsuario, name='guia_usuario'),
    path('emitir_voto/', views.emitir_voto, name='emitir_voto'),
    #path('administracion/', views.Administracion, name='administracion'),
    #path('subir-excel/', views.subir_excel, name='subir_excel'),
    path('descargar-plantilla/', views.descargar_plantilla, name='descargar_plantilla'),
    path('logout/', LogoutView.as_view(next_page='login'), name='logout'),
    path('nuevo_usuario/', views.nuevo_usuario, name='nuevo_usuario'),
    path('inscribir_usuarios_censo/', views.inscribir_usuarios_censo, name='inscribir_usuarios_censo'),
    path('mandar_incidencia/', views.MandarIncidenciaCenso, name='MandarIncidenciaCenso'),
    path('gestionar_votaciones/', views.gestionar_votaciones,name='gestionar_votaciones'),
    #path('asignar_censo_votacion/', views.asignar_censo_votacion, name='asignar_censo_votacion'),
    path('crear_candidatura/',views.crear_candidatura,name='crear_candidatura'),
    #path('inscribir_usuarios/', views.asignar_usuarios_votacion,name='asignar_usuarios_votacion'),
    path('notificar_usuarios/', views.notificar_usuarios_votacion, name='notificar_usuarios_votacion'),
    path('sortear_mesa/', views.sortear_mesa, name='sortear_mesa'),
    path('eliminar_candidatura/', views.eliminar_candidaturas, name='eliminar_candidaturas'),
    path('asignar_certificado_mesa/', views.asignar_certificado_mesa, name='asignar_certificado_mesa'),
    path('crear_certificado_personal/', views.crear_certificado_personal, name='crear_certificado_personal'),
    path('cambiar_contrasena/', views.cambiar_contraseña, name='cambiar_contraseña'),
    path('modificar_contraseña/', views.modificar_contraseña, name='modificar_contraseña'),
    path('certificar_voto/', views.certificar_voto, name='certificar_voto'),
    path('estadisticasVotacion/', views.estadisticasVotacion, name='estadisticasVotacion'),
    path('recuentoVotacion/',views.recuentoVotacion,name='recuentoVotacion'),
    #path('Incidencias/',views.Incidencias, name='incidencias'),
    path('nuevaVotacion/',views.nueva_votacion,name='nueva_votacion')
] 
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)