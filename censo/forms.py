from django import forms
from .models import Candidatura,Usuario

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
