from django.db import models
from mdeditor.fields import MDTextField
from django.conf import settings
import markdown

class Book(models.Model):
    title = models.CharField(max_length=200)
    author = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    pub_date = models.DateTimeField('date published')
    cover_image = models.ImageField(upload_to='book_covers/', blank=True, null=True, verbose_name='封面图片')
    is_published = models.BooleanField(default=False, verbose_name='发布状态', help_text='True表示已发布，False表示未发布')
    # user = models.ForeignKey(
    #     settings.AUTH_USER_MODEL,
    #     on_delete=models.CASCADE,
    #     related_name='books',
    #     verbose_name='创建用户',
    #     null=True,
    #     blank=True
    # )
    
    def __str__(self):
        return self.title

class Article(models.Model):
    book = models.ForeignKey(Book, on_delete=models.CASCADE, related_name='articles', blank=True, null=True)
    title = models.CharField(max_length=200)
    content = MDTextField()
    pub_date = models.DateTimeField('date published')
    def __str__(self):
        return self.title
    
    def get_markdown_content(self):
        extensions = [
            'markdown.extensions.extra',
            'markdown.extensions.codehilite',
            'markdown.extensions.fenced_code',
            'markdown.extensions.tables',
            'markdown.extensions.admonition',
            'markdown.extensions.smarty'
        ]
        
        # 配置代码高亮
        extension_configs = {
            'markdown.extensions.codehilite': {
                'linenums': True,
                'guess_lang': True,
                'use_pygments': True,
                'pygments_style': 'github-dark'
            }
        }
        
        return markdown.markdown(self.content, extensions=extensions, extension_configs=extension_configs)


# 权限审计日志模型
class PermissionAuditLog(models.Model):
    """权限审计日志模型，记录超级管理员权限的使用情况"""
    ACTION_CHOICES = [
        ('CREATE_USER', '创建用户'),
        ('UPDATE_USER', '更新用户'),
        ('DELETE_USER', '删除用户'),
        ('GRANT_PERMISSION', '授予权限'),
        ('REVOKE_PERMISSION', '撤销权限'),
        ('SYSTEM_INIT', '系统初始化'),
        ('ACCESS_ADMIN', '访问管理页面'),
        ('MODIFY_BOOK', '修改书籍'),
        ('MODIFY_ARTICLE', '修改文章'),
        ('DELETE_BOOK', '删除书籍'),
        ('DELETE_ARTICLE', '删除文章'),
    ]
    
    STATUS_CHOICES = [
        ('SUCCESS', '成功'),
        ('FAILED', '失败'),
        ('DENIED', '拒绝'),
    ]
    
    user = models.ForeignKey(
        'auth.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name='操作用户',
        related_name='audit_logs'
    )
    action = models.CharField(
        max_length=50,
        choices=ACTION_CHOICES,
        verbose_name='操作类型'
    )
    target_user = models.ForeignKey(
        'auth.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name='目标用户',
        related_name='target_logs'
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='SUCCESS',
        verbose_name='操作状态'
    )
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        verbose_name='IP地址'
    )
    user_agent = models.TextField(
        blank=True,
        verbose_name='用户代理'
    )
    details = models.JSONField(
        default=dict,
        blank=True,
        verbose_name='详细信息'
    )
    error_message = models.TextField(
        blank=True,
        verbose_name='错误信息'
    )
    timestamp = models.DateTimeField(
        auto_now_add=True,
        verbose_name='操作时间'
    )
    
    class Meta:
        verbose_name = '权限审计日志'
        verbose_name_plural = '权限审计日志'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['action', 'timestamp']),
            models.Index(fields=['status', 'timestamp']),
        ]
    
    def __str__(self):
        return f'{self.user} - {self.action} - {self.timestamp}'


# 系统配置模型
class SystemConfig(models.Model):
    """系统配置模型，用于存储系统级别的配置信息"""
    key = models.CharField(
        max_length=100,
        unique=True,
        verbose_name='配置键'
    )
    value = models.TextField(
        verbose_name='配置值'
    )
    description = models.TextField(
        blank=True,
        verbose_name='描述'
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name='创建时间'
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name='更新时间'
    )
    
    class Meta:
        verbose_name = '系统配置'
        verbose_name_plural = '系统配置'
    
    def __str__(self):
        return f'{self.key}: {self.value}'