from django import forms
from .models import Candidatura, Incidencia,Usuario,Votacion,Noticias,CalendarioVotacion,CensoVotacion,CensoUsuario
from django.core.exceptions import ValidationError
from datetime import timedelta

class LoginForm(forms.Form):
    documento_fiscal = forms.CharField(
        label='Documento Fiscal',
        max_length=150,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Ingresa tu Documento Fiscal',
        })
    )
    password = forms.CharField(
        label='Contraseña',
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Ingresa tu contraseña',
        })
    )

class NuevoUsuarioForm(forms.Form):
    Nombre=forms.CharField(
        label='Nombre Usuario',
        max_length=50,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Ingresa el nombre del usuario',
        })
    )
    Apellidos= forms.CharField(
        label='Apellidos Usuario',
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Ingresa los apellidos del usuario',
        })
    )
    DocumentoFiscal=forms.CharField(
        label='Documento Fiscal',
        max_length=12,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Ingresa tu Documento Fiscal',
        })
    )
    Email= forms.EmailField(
        label="Email",
        max_length=100,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Ingresa el email del usuario',
        })
    )
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.update({'class': 'form-control'})

class AdminCrearUsuarioForm(forms.Form):
    Nombre = forms.CharField(
        label='Nombre',
        max_length=50,
        widget=forms.TextInput(attrs={'class': 'form-control'})
    )
    Apellidos = forms.CharField(
        label='Apellidos',
        max_length=100,
        widget=forms.TextInput(attrs={'class': 'form-control'})
    )
    DocumentoFiscal = forms.CharField(
        label='Documento Fiscal',
        max_length=12,
        widget=forms.TextInput(attrs={'class': 'form-control'})
    )
    email = forms.EmailField(
        label='Email',
        max_length=100,
        widget=forms.EmailInput(attrs={'class': 'form-control'})
    )
    password = forms.CharField(
        label='Contraseña inicial',
        widget=forms.PasswordInput(attrs={'class': 'form-control'})
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.setdefault('class', 'form-control')          

class NuevaCandidaturaForm(forms.ModelForm):
    usuarios = forms.ModelMultipleChoiceField(
        queryset=Usuario.objects.none(),
        widget=forms.SelectMultiple(attrs={"class": "form-select", "size": "5"}),
        required=True,
        help_text="Selecciona 1 usuario si es individual, de 2 a 5 si es múltiple."
    )

    class Meta:
        model = Candidatura
        fields = ["NombreCandidatura", "TipoCandidatura", "Descripcion"] 

        widgets = {
            "NombreCandidatura": forms.TextInput(attrs={"class": "form-control"}),
            "TipoCandidatura": forms.Select(attrs={"class": "form-select"}),
            "Descripcion": forms.Textarea(attrs={"class": "form-control", "rows": 3}),
        }

    def __init__(self, *args, votacion=None, **kwargs):
        super().__init__(*args, **kwargs)

        # Por defecto, no listar todos (evita listas gigantes)
        qs = Usuario.objects.none()

        # Si hay votación, filtramos usuarios al censo asociado
        if votacion is not None:
            cv = CensoVotacion.objects.filter(votacion=votacion).select_related("censo").first()
            if cv:
                qs = Usuario.objects.filter(
                    id__in=CensoUsuario.objects.filter(censo=cv.censo).values_list("usuario_id", flat=True)
                ).order_by("DocumentoFiscal")

        self.fields["usuarios"].queryset = qs

    def clean(self):
        cleaned_data = super().clean()
        tipo = cleaned_data.get("TipoCandidatura")
        usuarios = cleaned_data.get("usuarios")

        if not usuarios:
            raise forms.ValidationError("Debes seleccionar al menos un usuario.")

        n = usuarios.count()
        if tipo == "individual" and n != 1:
            raise forms.ValidationError("Una candidatura individual debe tener exactamente 1 usuario.")
        if tipo == "multiple" and (n < 2 or n > 5):
            raise forms.ValidationError("Una candidatura múltiple debe tener entre 2 y 5 usuarios.")
        return cleaned_data

class NuevaVotacionForm(forms.Form):
    tituloVotacion = forms.CharField(
        label="Titulo de la Votacion",
        max_length=200,
        widget=forms.TextInput(attrs={'placeholder':'Introduce el titulo de la votacion'})
    )
    numeroParticipantes = forms.IntegerField(
        label='Numero de participantes',
        min_value=10
    )
    basesVotacion = forms.FileField(
        label='Elige el fichero con las bases de la votacion'
    )
    descripcion = forms.CharField(
        label='Descripcion',
        widget=forms.TextInput(attrs={'rows':3, 'placeholder':'Descripcion de la votacion'})
    )

class MesaNoticiaForm(forms.ModelForm):
    class Meta:
        model = Noticias
        fields = ['TituloNoticia', 'TextoNoticia']
        labels = {
            'TituloNoticia': 'Título',
            'TextoNoticia': 'Texto',
        }
        widgets = {
            'TituloNoticia': forms.TextInput(attrs={'class': 'form-control'}),
            'TextoNoticia': forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
        }

class JuntaNoticiaForm(forms.ModelForm):
    class Meta:
        model = Noticias
        fields = [
            'TituloNoticia',
            'TextoNoticia',
            'IdVotacionRelacionada',
            'IdCensoRelacionada',
            'NoticiaApp',
        ]
        labels = {
            'TituloNoticia': 'Título',
            'TextoNoticia': 'Texto',
            'IdVotacionRelacionada': 'Votación relacionada',
            'IdCensoRelacionada': 'Censo relacionado',
            'NoticiaApp': 'Noticia de aplicación (global)',
        }
        widgets = {
            'TituloNoticia': forms.TextInput(attrs={'class': 'form-control'}),
            'TextoNoticia': forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
            'IdVotacionRelacionada': forms.NumberInput(attrs={'class': 'form-control'}),
            'IdCensoRelacionada': forms.NumberInput(attrs={'class': 'form-control'}),
            'NoticiaApp': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }

class NuevaIncidenciaForm(forms.ModelForm):
    class Meta:
        model = Incidencia
        fields = ['IncidenciaSolucionada', 'RespuestaAdministrador']
        labels = {
            'IncidenciaSolucionada': 'Incidencia resuelta',
            'RespuestaAdministrador': 'Respuesta / resolución',
        }
        widgets = {
            'IncidenciaSolucionada': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'RespuestaAdministrador': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Escribe la respuesta o resolución que verá el usuario…',
            }),
        }

class JuntaIncidenciaForm(forms.ModelForm):
    class Meta:
        model = Incidencia
        fields = ['IncidenciaSolucionada', 'RespuestaAdministrador']
        labels = {
            'IncidenciaSolucionada': 'Incidencia resuelta',
            'RespuestaAdministrador': 'Respuesta / resolución',
        }
        widgets = {
            'IncidenciaSolucionada': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'RespuestaAdministrador': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Escribe la respuesta o resolución que verá el usuario…',
            }),
        }

class CalendarioVotacionForm(forms.ModelForm):
    class Meta:
        model = CalendarioVotacion
        fields=[
            "fecha_censos","duracion_censos_dias",
            "fecha_campaña", "duracion_campaña_dias",
            "fecha_votacion", "duracion_votacion_dias",
            "fecha_recuento", "duracion_recuento_dias",
            "fecha_publicacion_resultados"
        ]
        widgets={
            "fecha_censos": forms.DateInput(attrs={"type": "date", "class": "form-control"}),
            "fecha_campaña": forms.DateInput(attrs={"type": "date", "class": "form-control"}),
            "fecha_votacion": forms.DateInput(attrs={"type": "date", "class": "form-control"}),
            "fecha_recuento": forms.DateInput(attrs={"type": "date", "class": "form-control"}),
            "fecha_publicacion_resultados": forms.DateInput(attrs={"type": "date", "class": "form-control"}),
            "duracion_censos_dias": forms.NumberInput(attrs={"class": "form-control", "min": 1}),
            "duracion_campaña_dias": forms.NumberInput(attrs={"class": "form-control", "min": 1}),
            "duracion_votacion_dias": forms.NumberInput(attrs={"class": "form-control", "min": 1}),
            "duracion_recuento_dias": forms.NumberInput(attrs={"class": "form-control", "min": 1}),
        }
    def clean(self):
        cleaned=super().clean()
        fc= cleaned.get("fecha_censos")
        dc= cleaned.get("duracion_censos_dias")
        fca= cleaned.get("fecha_campaña")
        dca= cleaned.get("duracion_campaña_dias")
        fv= cleaned.get("fecha_votacion")
        dv= cleaned.get("duracion_votacion_dias")
        fr= cleaned.get("fecha_recuento")
        dr=cleaned.get("duracion_recuento_dias")
        fpub = cleaned.get("fecha_publicacion_resultados")
        if not all([fc,dc,fca,dca,fv,dv,fr,dr,fpub]):

            return cleaned  
        def fin(inicio, duracion):

            return inicio + timedelta(days=int(duracion)-1)
        fin_censos=fin(fc,dc)
        fin_campaña=fin(fca,dca)
        fin_votacion=fin(fv,dv)
        fin_recuento=fin(fr,dr)
        #condiciones de validacion
        def check_fecha_consecutiva(fin_anterior, inicio_siguiente, nombre_siguiente):
            if inicio_siguiente < fin_anterior:
                raise ValidationError(f"La fase '{nombre_siguiente}' no puede comenzar antes del fin de la anterior")
            if inicio_siguiente > (fin_anterior + timedelta(days=1)):
                raise ValidationError(f"La fase '{nombre_siguiente}' debe empezar como máximo un dia después de la anterior")
        check_fecha_consecutiva(fin_censos, fca, "Campaña Electoral")
        check_fecha_consecutiva(fin_campaña, fv, "Votacion")
        check_fecha_consecutiva(fin_votacion, fr, "Recuento")
        check_fecha_consecutiva(fin_recuento,fpub,"Publicacion de resultados")
        return cleaned

class AsignarDirectorCampañaForm(forms.Form):
    candidatura = forms.ModelChoiceField(
        queryset=Candidatura.objects.none(),
        label="Candidatura",
        widget=forms.Select(attrs={"class": "form-select"})
    )
    director = forms.ModelChoiceField(
        queryset=Usuario.objects.all().order_by("DocumentoFiscal"),
        label="Usuario (director de campaña)",
        widget=forms.Select(attrs={"class": "form-select"})
    )
    def __init__(self, *args, **kwargs):
        candidaturas_qs = kwargs.pop("candidaturas_qs", None)
        super().__init__(*args, **kwargs)
        if candidaturas_qs is not None:
            self.fields["candidatura"].queryset = candidaturas_qs