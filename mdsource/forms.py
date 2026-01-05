from django import forms
from django.utils import timezone
from django.contrib.auth.forms import PasswordChangeForm as DjangoPasswordChangeForm
from .models import Article, Book

class ArticleForm(forms.ModelForm):
    class Meta:
        model = Article
        fields = ['title', 'book', 'content', 'pub_date']
        widgets = {
            'pub_date': forms.DateTimeInput(attrs={'type': 'datetime-local'}),
        }
    
    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        
        # 创建模式下，设置默认发布时间为当前时间
        if not self.instance.pk:
            self.fields['pub_date'].initial = timezone.now()
        
        if user is not None:
            # 创建模式：只显示当前用户且未发布的书籍
            if not self.instance.pk:
                self.fields['book'].queryset = Book.objects.filter(
                    author=user,
                    is_published=False
                ).order_by('-pub_date')
            else:
                # 编辑模式：显示所有书籍
                self.fields['book'].queryset = Book.objects.all()
        else:
            # 如果没有用户信息，显示所有书籍
            self.fields['book'].queryset = Book.objects.all()

class BookForm(forms.ModelForm):
    class Meta:
        model = Book
        fields = ['title', 'author', 'description', 'cover_image', 'is_published', 'pub_date']
        widgets = {
            'pub_date': forms.DateTimeInput(attrs={'type': 'datetime-local'}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # 创建模式下，设置默认发布时间为当前时间
        if not self.instance.pk:
            self.fields['pub_date'].initial = timezone.now()

class PasswordChangeForm(DjangoPasswordChangeForm):
    """自定义密码修改表单，取消密码复杂度验证"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # 移除所有密码复杂度验证器
        self.fields['new_password1'].validators = []
        self.fields['new_password2'].validators = []
    
    def clean_new_password1(self):
        """自定义新密码验证：只需要不少于6个非空字符"""
        password1 = self.cleaned_data.get('new_password1')
        
        # 验证密码长度不少于6个字符
        if len(password1) < 6:
            raise forms.ValidationError('密码长度不能少于6个字符')
        
        # 验证密码不全是空格
        if password1.strip() == '':
            raise forms.ValidationError('密码不能全是空格')
        
        return password1