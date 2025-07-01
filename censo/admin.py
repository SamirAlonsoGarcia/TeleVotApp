from django.contrib import admin
from .models import Censo, Candidatura, Votacion, MesaElectoral, Noticias, Usuario, Incidencia, CensoUsuario, CensoVotacion, InscritosVotacion, IntegrantesCandidatura, CandidatosNombrados, IntegrantesMesa, Certificado, Voto
# Register your models here.

admin.site.register(Censo)
admin.site.register(Candidatura)
admin.site.register(Votacion)
admin.site.register(MesaElectoral)
admin.site.register(Noticias)
admin.site.register(Usuario)
admin.site.register(Incidencia)
admin.site.register(CensoUsuario)
admin.site.register(CensoVotacion)
admin.site.register(InscritosVotacion)
admin.site.register(IntegrantesCandidatura)
admin.site.register(CandidatosNombrados)
admin.site.register(IntegrantesMesa)
admin.site.register(Certificado)
admin.site.register(Voto)