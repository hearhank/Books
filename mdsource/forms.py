from django import forms
from django.utils import timezone
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