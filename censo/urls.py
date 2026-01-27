from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth.views import LogoutView
from . import views

urlpatterns=[
    path('', views.login_view, name='login'),
    path('seleccionar-rol/', views.seleccionar_rol, name='seleccionar_rol'),
    # urls separadas por roles para claridad
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
    path('junta/votaciones/asignar-director/', views.Junta_vot_asignar_director, name='Junta_vot_asignar_director'),
    path('junta/votaciones/toggle-estado/', views.Junta_vot_toggle_estado, name='Junta_vot_toggle_estado'),
    path('junta/votaciones/toggle-recuento/', views.junta_vot_toggle_recuento, name='Junta_vot_toggle_recuento'),
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
    path('elector/votaciones/estadisticas/activa/', views.elector_estadisticas_activa, name='Elector_estadisticas_activa'),
    path('elector/votaciones/estadisticas/finalizada/', views.elector_estadisticas_finalizada, name='Elector_estadisticas_finalizada'),
    # incidencias y censo
    path('elector/censos/incidencia/', views.MandarIncidenciaCenso, name='Elector_incidencia_censo'),
    path('elector/incidencias/', views.elector_incidencias, name='Elector_incidencias'),
    path('elector/votaciones/incidencia/', views.MandarIncidenciaVotacion, name='Elector_incidencia_votacion'),
    # certificados personales
    path('elector/certificados/crear/', views.crear_certificado_personal, name='Elector_crear_certificado'),
    path('elector/votaciones/certificar-voto/', views.certificar_voto, name='Elector_certificar_voto'),
    # descargar plantilla censo
    path('descargar-plantilla/', views.descargar_plantilla, name='descargar_plantilla'),
    # guia de usuario para tqodos los roles, va en el footer
    path('guia-usuario/', views.GuiaUsuario, name='Guia_usuario_global'),
    # modificar contraseña
    path('cambiar_contrasena/', views.cambiar_contraseña, name='cambiar_contraseña'),
    path('modificar_contraseña/', views.modificar_contraseña, name='modificar_contraseña'),
    # cerrar sesión
    path('logout/', LogoutView.as_view(next_page='login'), name='logout'),
] 
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)