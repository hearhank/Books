"""
权限控制模块
包含权限验证装饰器、中间件和辅助函数
"""
from functools import wraps
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


def get_client_ip(request):
    """获取客户端IP地址"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def is_first_user():
    """检查是否是第一个用户"""
    from django.contrib.auth.models import User
    return User.objects.count() == 0


def is_super_admin(user):
    """检查用户是否是超级管理员"""
    return user.is_authenticated and user.is_superuser


def log_permission_audit(user, action, status='SUCCESS', target_user=None, 
                         request=None, details=None, error_message=None):
    """记录权限审计日志"""
    from .models import PermissionAuditLog
    
    try:
        audit_log = PermissionAuditLog.objects.create(
            user=user,
            action=action,
            target_user=target_user,
            status=status,
            ip_address=get_client_ip(request) if request else None,
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:500] if request else '',
            details=details or {},
            error_message=error_message or ''
        )
        logger.info(f"权限审计日志已记录: {user} - {action} - {status}")
    except Exception as e:
        logger.error(f"记录权限审计日志失败: {str(e)}")


def super_admin_required(view_func):
    """
    超级管理员权限验证装饰器
    只有超级管理员才能访问被装饰的视图
    """
    @wraps(view_func)
    @login_required
    def _wrapped_view(request, *args, **kwargs):
        # 检查用户是否是超级管理员
        if not request.user.is_superuser:
            # 记录权限拒绝日志
            log_permission_audit(
                user=request.user,
                action='ACCESS_ADMIN',
                status='DENIED',
                request=request,
                details={'path': request.path, 'method': request.method}
            )
            
            # 返回权限拒绝响应
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({
                    'success': False,
                    'error': '需要超级管理员权限'
                }, status=403)
            else:
                raise PermissionDenied('需要超级管理员权限')
        
        # 记录访问成功日志
        log_permission_audit(
            user=request.user,
            action='ACCESS_ADMIN',
            status='SUCCESS',
            request=request,
            details={'path': request.path, 'method': request.method}
        )
        
        return view_func(request, *args, **kwargs)
    
    return _wrapped_view


def staff_required(view_func):
    """
    员工权限验证装饰器
    只有员工（包括超级管理员）才能访问被装饰的视图
    """
    @wraps(view_func)
    @login_required
    def _wrapped_view(request, *args, **kwargs):
        # 检查用户是否是员工
        if not request.user.is_staff:
            # 记录权限拒绝日志
            log_permission_audit(
                user=request.user,
                action='ACCESS_ADMIN',
                status='DENIED',
                request=request,
                details={'path': request.path, 'method': request.method}
            )
            
            # 返回权限拒绝响应
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({
                    'success': False,
                    'error': '需要员工权限'
                }, status=403)
            else:
                raise PermissionDenied('需要员工权限')
        
        return view_func(request, *args, **kwargs)
    
    return _wrapped_view


def first_user_or_super_admin(view_func):
    """
    第一个用户或超级管理员权限验证装饰器
    用于用户注册/创建时的权限验证
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        # 如果是第一个用户，允许创建
        if is_first_user():
            return view_func(request, *args, **kwargs)
        
        # 如果不是第一个用户，需要超级管理员权限
        if not request.user.is_authenticated or not request.user.is_superuser:
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({
                    'success': False,
                    'error': '只有超级管理员才能创建用户'
                }, status=403)
            else:
                raise PermissionDenied('只有超级管理员才能创建用户')
        
        return view_func(request, *args, **kwargs)
    
    return _wrapped_view


def prevent_self_deletion(view_func):
    """
    防止用户删除自己的装饰器
    """
    @wraps(view_func)
    @login_required
    def _wrapped_view(request, *args, **kwargs):
        user_id = kwargs.get('user_id') or request.POST.get('user_id')
        
        if user_id and int(user_id) == request.user.id:
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({
                    'success': False,
                    'error': '不能删除自己的账户'
                }, status=400)
            else:
                from django.contrib import messages
                messages.error(request, '不能删除自己的账户')
                return redirect(request.META.get('HTTP_REFERER', '/'))
        
        return view_func(request, *args, **kwargs)
    
    return _wrapped_view


def prevent_self_disable(view_func):
    """
    防止用户禁用自己的装饰器
    """
    @wraps(view_func)
    @login_required
    def _wrapped_view(request, *args, **kwargs):
        user_id = kwargs.get('user_id') or request.POST.get('user_id')
        is_active = request.POST.get('is_active')
        
        if (user_id and int(user_id) == request.user.id and 
            is_active == 'off'):
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({
                    'success': False,
                    'error': '不能禁用自己的账户'
                }, status=400)
            else:
                from django.contrib import messages
                messages.error(request, '不能禁用自己的账户')
                return redirect(request.META.get('HTTP_REFERER', '/'))
        
        return view_func(request, *args, **kwargs)
    
    return _wrapped_view


class PermissionAuditMiddleware:
    """
    权限审计中间件
    记录所有关键操作的审计日志
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # 处理请求
        response = self.get_response(request)
        
        # 记录关键操作的审计日志
        self._audit_sensitive_operations(request, response)
        
        return response
    
    def _audit_sensitive_operations(self, request, response):
        """审计敏感操作"""
        # 注意：详细的审计日志已经在视图中记录，中间件不再重复记录
        # 这里保留空方法以备将来需要额外的审计功能
        pass
    
    def _determine_action(self, path, method):
        """根据路径和方法确定操作类型"""
        if 'delete-user' in path:
            return 'DELETE_USER'
        elif 'user-form' in path:
            if method == 'POST':
                return 'UPDATE_USER' if 'user_id' in path or 'user_id' in getattr(method, '__dict__', {}) else 'CREATE_USER'
        elif 'admins' in path:
            return 'ACCESS_ADMIN'
        return 'UNKNOWN'


class PermissionRequiredMixin:
    """
    权限要求的混合类
    用于基于类的视图
    """
    required_permissions = []
    
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({
                'success': False,
                'error': '需要登录'
            }, status=401)
        
        # 检查是否是超级管理员
        if not request.user.is_superuser:
            log_permission_audit(
                user=request.user,
                action='ACCESS_ADMIN',
                status='DENIED',
                request=request,
                details={'path': request.path}
            )
            return JsonResponse({
                'success': False,
                'error': '需要超级管理员权限'
            }, status=403)
        
        log_permission_audit(
            user=request.user,
            action='ACCESS_ADMIN',
            status='SUCCESS',
            request=request,
            details={'path': request.path}
        )
        
        return super().dispatch(request, *args, **kwargs)


def check_user_permission(user, required_permission):
    """
    检查用户是否具有特定权限
    """
    if user.is_superuser:
        return True
    
    if user.is_staff and required_permission in ['view', 'edit']:
        return True
    
    return False


def get_user_role(user):
    """
    获取用户角色
    """
    if user.is_superuser:
        return '超级管理员'
    elif user.is_staff:
        return '员工'
    else:
        return '普通用户'


