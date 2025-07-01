from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth.views import LogoutView
from . import views

urlpatterns=[
    path('', views.login_view, name='login'),
    path('Inicio/', views.Inicio, name='inicio'),
    path('Censo/', views.Censo_view, name='censos'),
    path('Certificados/', views.Certificados, name='certificados'),
    path('Votaciones/', views.Votacion_view, name='votaciones'),
    path('Noticias/', views.Noticia, name='noticias'),
    path('Guia_de_Usuario/', views.GuiaUsuario, name='guia_usuario'),
    path('emitir_voto/', views.emitir_voto, name='emitir_voto'),
    path('administracion/', views.Administracion, name='administracion'),
    path('subir-excel/', views.subir_excel, name='subir_excel'),
    path('descargar-plantilla/', views.descargar_plantilla, name='descargar_plantilla'),
    path('logout/', LogoutView.as_view(next_page='login'), name='logout'),
    path('nuevo_usuario/', views.nuevo_usuario, name='nuevo_usuario'),
    path('inscribir_usuarios_censo/', views.inscribir_usuarios_censo, name='inscribir_usuarios_censo'),
    path('mandar_incidencia/', views.MandarIncidenciaCenso, name='MandarIncidenciaCenso'),
    path('gestionar_votaciones/', views.gestionar_votaciones,name='gestionar_votaciones'),
    path('asignar_censo_votacion/', views.asignar_censo_votacion, name='asignar_censo_votacion'),
    path('crear_candidatura/',views.crear_candidatura,name='crear_candidatura'),
    path('inscribir_usuarios/', views.asignar_usuarios_votacion,name='asignar_usuarios_votacion'),
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
    path('Incidencias/',views.Incidencias, name='incidencias')
] 
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)