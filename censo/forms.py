from django import forms
from .models import Candidatura, Incidencia,Usuario,Votacion,Noticias

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
        queryset=Usuario.objects.all(),
        widget=forms.CheckboxSelectMultiple,
        required=True,
        help_text="Selecciona 1 usuario si es individual, hasta 5 si es múltiple"
    )
    class Meta:
        model = Candidatura
        fields = ['NombreCandidatura','TipoCandidatura','Descripcion','usuarios']

    def clean(self):
        cleaned_data = super().clean()
        tipo = cleaned_data.get('tipo')
        usuarios = cleaned_data.get('usuarios')

        if tipo == 'individual' and usuarios.count() != 1:
            raise forms.ValidationError("Una candidatura individual debe tener exactamente un usuario.")
        if tipo == 'multiple' and (usuarios.count() < 2 or usuarios.count() > 5):
            raise forms.ValidationError("Una candidatura múltiple debe tener al menos 2 usuarios y como máximo 5.")
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