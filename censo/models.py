from datetime import timedelta
import django
from django.db import models
from django.db.models import Q
from django.contrib.auth.models import AbstractUser
from django.utils import timezone

# Create your models here.

class Censo(models.Model):
    IdCenso = models.AutoField(primary_key=True)
    NombreCenso = models.CharField(max_length=100, default='')
    Descripcion = models.CharField(max_length=200, default='')
    nCensados = models.IntegerField()
    FicheroAsociado= models.FileField()
    def __str__(self):
        return self.NombreCenso

class Votacion(models.Model):
    IdVotacion = models.AutoField(primary_key=True)
    TituloVotacion = models.CharField(max_length=100)
    NParticipantes = models.IntegerField()
    Resultado = models.CharField(max_length=13, default="Sin Resolver")
    Estado = models.BooleanField(default=False)
    RecuentoAutorizado = models.BooleanField(default=False)
    BasesVotacion = models.FileField()
    Descripcion = models.CharField(max_length=200)
    def __str__(self):
        return self.TituloVotacion

class Candidatura(models.Model):
    IdCandidatura = models.AutoField(primary_key=True)
    NombreCandidatura = models.CharField(default="")
    VALORES_CANDIDATURA = [
        ('individual', 'Individual'),
        ('multiple', 'Múltiple'),
    ]
    TipoCandidatura= models.CharField(max_length=10, choices=VALORES_CANDIDATURA)
    Descripcion = models.CharField(max_length=200)
    def __str__(self):
        return self.NombreCandidatura
    
class Certificado(models.Model):
    TIPO_CERTIFICADO = [
        ('usuario','Usuario'),
        ('mesa', 'MesaElectoral'),
    ]
    IdCertificado = models.AutoField(primary_key=True)
    TipoCertificado = models.CharField(max_length=10, choices=TIPO_CERTIFICADO)
    clave_publica = models.TextField(default="")
    clave_privada = models.TextField(null=True,blank=True)
    propietario_mesa = models.OneToOneField('MesaElectoral', on_delete=models.CASCADE, null=True, blank=True)
    propietario_usuario= models.OneToOneField('Usuario', on_delete=models.CASCADE, null=True, blank=True)
    fecha_creacion = models.DateTimeField(default=timezone.now)
    revocado = models.BooleanField(default=False)
    motivo_revocacion = models.CharField(max_length=200, null=True, blank=True)
    fecha_revocacion = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        if self.propietario_mesa:
            return f"Certificado Mesa: {self.propietario_mesa.NombreMesa}"
        elif self.propietario_usuario:
            return f"Certificado Usuario: {self.propietario_usuario.DocumentoFiscal}"
        return "Certificado sin propietario"

class Usuario(AbstractUser):
    Nombre = models.CharField(max_length=100)
    Apellidos = models.CharField(max_length=200)
    DocumentoFiscal = models.CharField(max_length=12,unique=True)
    email = models.EmailField(max_length=254, unique=True)
    IdEncriptado = models.CharField(max_length=64)
    primera_vez = models.BooleanField(default=True, null=False)
    USERNAME_FIELD = 'DocumentoFiscal'
    REQUIRED_FIELDS = ['username', 'email']
    
    def __str__(self):
        return self.DocumentoFiscal

class MesaElectoral(models.Model):
    IdMesa = models.AutoField(primary_key=True)
    IdVotacion = models.ForeignKey(Votacion,on_delete=models.CASCADE)
    NombreMesa = models.CharField(default="")
    Sorteada = models.BooleanField(default=False)
    certificado_visible = models.BooleanField(default=False)
    
    def __str__(self):
        return self.NombreMesa
    
class Noticias(models.Model):
    IdNoticia = models.AutoField(primary_key=True)
    TituloNoticia = models.CharField(default="")
    TextoNoticia = models.CharField(default="")
    IdVotacionRelacionada = models.ForeignKey(Votacion, on_delete=models.CASCADE, null=True, blank=True)
    IdCensoRelacionada = models.ForeignKey(Censo, on_delete=models.CASCADE, null=True, blank=True)
    NoticiaApp = models.BooleanField(default=False)
    def __str__(self):
        return self.TituloNoticia

class Voto(models.Model):
    IdVoto = models.AutoField(primary_key=True)
    IdVotacion = models.ForeignKey(Votacion, on_delete=models.CASCADE)
    idUsuario = models.ForeignKey(Usuario, on_delete=models.CASCADE, null=True, blank=True)
    hashVoto = models.CharField(default="", null=False)
    fecha_emision = models.DateTimeField(default=django.utils.timezone.now)
    def __str__(self):
        return self.hashVoto
    
class Incidencia(models.Model):
    IdIncidencia = models.AutoField(primary_key=True)
    IdUsuario = models.ForeignKey(Usuario, on_delete=models.CASCADE,null=False)
    IdCenso = models.ForeignKey(Censo,on_delete=models.CASCADE, null=True, blank=True)
    IdVotacion = models.ForeignKey(Votacion, on_delete=models.CASCADE, null=True, blank=True)
    TituloIncidencia = models.CharField(null=False)
    IncidenciaSolucionada = models.BooleanField(default=False)
    TextoIncidencia = models.CharField(null=False)
    FicheroIncidencia = models.FileField(null=True,blank=True)
    RespuestaAdministrador = models.TextField(blank=True, null=True)
    def __str__(self):
        return self.TituloIncidencia
    
#Clases para manejar las tablas intermedias de relaciones many to many

class CensoUsuario(models.Model):
    usuario = models.ForeignKey(Usuario, on_delete=models.CASCADE)
    censo = models.ForeignKey(Censo, on_delete=models.CASCADE)
    class Meta:
        unique_together = ('usuario', 'censo')

class CensoVotacion(models.Model):
    votacion = models.ForeignKey(Votacion, on_delete=models.CASCADE)
    censo = models.ForeignKey(Censo, on_delete=models.CASCADE)
    class Meta:
        unique_together = ('votacion', 'censo')

class InscritosVotacion(models.Model):
    usuario = models.ForeignKey(Usuario, on_delete=models.CASCADE)
    votacion = models.ForeignKey(Votacion, on_delete=models.CASCADE)
    class Meta:
        unique_together = ('usuario','votacion')

class CandidatosNombrados(models.Model):
    votacion = models.ForeignKey(Votacion, on_delete=models.CASCADE)
    candidatura = models.ForeignKey(Candidatura, on_delete=models.CASCADE)
    director= models.ForeignKey(Usuario, on_delete=models.SET_NULL, null=True, blank=True, related_name='director_campaña')

    class Meta:
        unique_together = ('votacion', 'candidatura')
        constraints = [
        models.UniqueConstraint(fields=['votacion', 'director'],condition=Q(director__isnull=False),name='unique_director_por_votacion')
    ]

class IntegrantesCandidatura(models.Model):
    usuario = models.ForeignKey(Usuario, on_delete=models.CASCADE)
    candidatura = models.ForeignKey(Candidatura, on_delete=models.CASCADE)
    class Meta:
        unique_together = ('usuario', 'candidatura') 

class IntegrantesMesa(models.Model):
    usuario = models.ForeignKey(Usuario,on_delete=models.CASCADE)
    mesa = models.ForeignKey(MesaElectoral,on_delete=models.CASCADE)
    class Meta:
        unique_together = ('usuario', 'mesa')

class RolUsuario(models.Model):
    ROL_USUARIO = [
        ('admin','Administrador'),
        ('elector','Elector'),
        ('mesa','MesaElectoral'),
        ('director', 'DirectorCampaña'),
        ('junta', 'JuntaElectoral'),
    ]
    usuario = models.ForeignKey(Usuario, on_delete=models.CASCADE)
    rol = models.CharField(max_length=15, choices=ROL_USUARIO)
    class Meta:
        unique_together = ('usuario', 'rol')

class ComunicacionDirector(models.Model):
    #temporalmente se marca como posible null=True, blank=True mientras se hace el metodo de asignacion de la candidatura y votacion desde manejar votacion
    campaña = models.ForeignKey(CandidatosNombrados, on_delete=models.CASCADE, null=True, blank=True)
    director = models.ForeignKey(Usuario, on_delete=models.CASCADE)
    mensaje = models.TextField()
    fecha_envio = models.DateTimeField(default=timezone.now)
    imagen_adjunto = models.ImageField(upload_to='comunicaciones_director/', null=True, blank=True)

    def __str__(self):
        return f"Comunicación de {self.director.DocumentoFiscal} - {self.fecha_envio}"
    
class CalendarioVotacion(models.Model):
    votacion = models.OneToOneField('Votacion', on_delete=models.CASCADE, related_name='calendario')

    creado_en = models.DateTimeField(auto_now_add=True)
    fecha_no_modificacion = models.DateField()

    # Fases (inicio + duración)
    fecha_censos = models.DateField()
    duracion_censos_dias = models.PositiveIntegerField(default=1)

    fecha_campaña = models.DateField()
    duracion_campaña_dias = models.PositiveIntegerField(default=1)

    fecha_votacion = models.DateField()
    duracion_votacion_dias = models.PositiveIntegerField(default=1)

    fecha_recuento = models.DateField()
    duracion_recuento_dias = models.PositiveIntegerField(default=1)

    fecha_publicacion_resultados = models.DateField()

    def save(self, *args, **kwargs):
        # Si no se define explícitamente, por defecto: 1 día después de crearlo
        if not self.fecha_no_modificacion:
            self.fecha_no_modificacion = (timezone.now() + timedelta(days=1)).date()
        super().save(*args, **kwargs)

    def bloqueado(self):
        #True si ya no se puede modificar
        return timezone.now().date() > self.fecha_no_modificacion

    def __str__(self):
        return f"Calendario {self.votacion}"