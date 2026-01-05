from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('articles/', views.article_list, name='article_list'),
    path('articles/<int:article_id>/', views.article_detail, name='article_detail'),
    path('articles/create/', views.article_create, name='article_create'),
    path('articles/<int:article_id>/edit/', views.article_edit, name='article_edit'),
    path('articles/<int:article_id>/content/', views.article_content, name='article_content'),
    path('books/create/', views.book_create, name='book_create'),
    path('books/<int:book_id>/', views.book_detail, name='book_detail'),
    path('books/<int:book_id>/edit/', views.book_edit, name='book_edit'),
    path('books/<int:book_id>/toggle-published/', views.toggle_book_published, name='toggle_book_published'),
    path('admins/', views.admins, name='admins'),
    path('admins/subpages/user-form/', views.user_form, name='user_form'),
    path('admins/subpages/delete-user/', views.delete_user, name='delete_user'),
    path('admins/subpages/delete-book/', views.delete_book, name='delete_book'),
    path('admins/subpages/delete-article/', views.delete_article, name='delete_article'),
    path('admins/subpages/<str:module_name>/', views.subpage_loader, name='subpage_loader'),
    path('admins/logs/', views.audit_logs, name='audit_logs'),
    path('accounts/login/', views.user_login, name='login'),
    path('accounts/logout/', views.user_logout, name='logout'),
    path('accounts/change-password/', views.change_password, name='change_password'),
]