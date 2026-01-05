from django.contrib import admin
from .models import Book, Article, PermissionAuditLog, SystemConfig

admin.site.register(Book)
admin.site.register(Article, admin.ModelAdmin)


@admin.register(PermissionAuditLog)
class PermissionAuditLogAdmin(admin.ModelAdmin):
    """权限审计日志管理界面"""
    list_display = ['user', 'action', 'status', 'target_user', 'ip_address', 'timestamp']
    list_filter = ['action', 'status', 'timestamp']
    search_fields = ['user__username', 'target_user__username', 'ip_address']
    readonly_fields = ['user', 'action', 'target_user', 'status', 'ip_address', 
                      'user_agent', 'details', 'error_message', 'timestamp']
    date_hierarchy = 'timestamp'
    
    def has_add_permission(self, request):
        # 禁止手动添加审计日志
        return False
    
    def has_change_permission(self, request, obj=None):
        # 禁止修改审计日志
        return False
    
    def has_delete_permission(self, request, obj=None):
        # 只有超级管理员可以删除审计日志
        return request.user.is_superuser


@admin.register(SystemConfig)
class SystemConfigAdmin(admin.ModelAdmin):
    """系统配置管理界面"""
    list_display = ['key', 'value', 'description', 'created_at', 'updated_at']
    search_fields = ['key', 'description']
    list_filter = ['created_at', 'updated_at']
    
    def has_add_permission(self, request):
        # 只有超级管理员可以添加系统配置
        return request.user.is_superuser
    
    def has_change_permission(self, request, obj=None):
        # 只有超级管理员可以修改系统配置
        return request.user.is_superuser
    
    def has_delete_permission(self, request, obj=None):
        # 只有超级管理员可以删除系统配置
        return request.user.is_superuser