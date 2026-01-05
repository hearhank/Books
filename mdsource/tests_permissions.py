"""
权限控制系统测试用例
测试用户权限控制、审计日志和权限验证功能
"""
from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from mdsource.models import PermissionAuditLog, SystemConfig
from mdsource.permissions import is_first_user, is_super_admin, log_permission_audit
import json


class PermissionControlTestCase(TestCase):
    """权限控制基础测试用例"""
    
    def setUp(self):
        """测试前准备"""
        self.client = Client()
        # 创建超级管理员
        self.super_admin = User.objects.create_user(
            username='admin',
            password='admin123',
            is_superuser=True,
            is_staff=True
        )
        # 创建普通用户
        self.normal_user = User.objects.create_user(
            username='user',
            password='user123',
            is_superuser=False,
            is_staff=False
        )
    
    def tearDown(self):
        """测试后清理"""
        User.objects.all().delete()
        PermissionAuditLog.objects.all().delete()
        SystemConfig.objects.all().delete()


class FirstUserPermissionTestCase(PermissionControlTestCase):
    """第一个用户权限测试用例"""
    
    def test_is_first_user_empty_database(self):
        """测试空数据库时是否是第一个用户"""
        User.objects.all().delete()
        self.assertTrue(is_first_user())
    
    def test_is_first_user_with_users(self):
        """测试有用户时是否不是第一个用户"""
        self.assertFalse(is_first_user())
    
    def test_first_user_auto_superadmin(self):
        """测试第一个用户自动获得超级管理员权限"""
        User.objects.all().delete()
        
        # 通过user_form视图创建第一个用户（而不是直接使用create_user）
        response = self.client.post('/admins/subpages/user-form/', {
            'username': 'first',
            'password1': 'first123',
            'password2': 'first123'
        })
        
        # 验证用户是否创建成功
        self.assertTrue(User.objects.filter(username='first').exists())
        first_user = User.objects.get(username='first')
        
        # 验证第一个用户是否自动获得超级管理员权限
        self.assertTrue(first_user.is_superuser)
        self.assertTrue(first_user.is_staff)
        self.assertTrue(first_user.is_active)
    
    def test_second_user_not_superadmin(self):
        """测试第二个用户不会自动获得超级管理员权限"""
        # 创建第二个用户
        second_user = User.objects.create_user(
            username='second',
            password='second123'
        )
        
        # 验证第二个用户不会自动获得超级管理员权限
        self.assertFalse(second_user.is_superuser)
        self.assertFalse(second_user.is_staff)
        self.assertTrue(second_user.is_active)


class PermissionDecoratorTestCase(PermissionControlTestCase):
    """权限装饰器测试用例"""
    
    def test_super_admin_required_with_admin(self):
        """测试超级管理员装饰器对管理员用户"""
        self.client.login(username='admin', password='admin123')
        response = self.client.get('/admins/')
        self.assertEqual(response.status_code, 200)
    
    def test_super_admin_required_with_normal_user(self):
        """测试超级管理员装饰器对普通用户"""
        self.client.login(username='user', password='user123')
        response = self.client.get('/admins/')
        self.assertEqual(response.status_code, 403)
    
    def test_super_admin_required_without_login(self):
        """测试超级管理员装饰器对未登录用户"""
        response = self.client.get('/admins/')
        self.assertEqual(response.status_code, 302)  # 重定向到登录页面
    
    def test_user_creation_with_super_admin(self):
        """测试超级管理员创建用户"""
        self.client.login(username='admin', password='admin123')
        
        response = self.client.post('/admins/subpages/user-form/', {
            'username': 'newuser',
            'first_name': 'New',
            'last_name': 'User',
            'email': 'new@example.com',
            'password1': 'newuser123',
            'password2': 'newuser123',
            'is_active': 'on',
            'is_staff': 'off',
            'is_superuser': 'off'
        })
        
        # 验证用户是否创建成功
        self.assertTrue(User.objects.filter(username='newuser').exists())
        new_user = User.objects.get(username='newuser')
        self.assertFalse(new_user.is_superuser)
        self.assertFalse(new_user.is_staff)
    
    def test_user_creation_with_normal_user(self):
        """测试普通用户创建用户（应该被拒绝）"""
        self.client.login(username='user', password='user123')
        
        response = self.client.post('/admins/subpages/user-form/', {
            'username': 'newuser',
            'password1': 'newuser123',
            'password2': 'newuser123'
        })
        
        # 验证是否返回403错误
        self.assertEqual(response.status_code, 403)
        # 验证用户是否未被创建
        self.assertFalse(User.objects.filter(username='newuser').exists())
    
    def test_delete_user_with_super_admin(self):
        """测试超级管理员删除用户"""
        self.client.login(username='admin', password='admin123')
        
        # 创建一个待删除的用户
        user_to_delete = User.objects.create_user(
            username='todelete',
            password='delete123'
        )
        
        response = self.client.post('/admins/subpages/delete-user/', {
            'user_id': user_to_delete.id
        })
        
        # 验证用户是否被删除
        self.assertFalse(User.objects.filter(username='todelete').exists())
    
    def test_delete_user_with_normal_user(self):
        """测试普通用户删除用户（应该被拒绝）"""
        self.client.login(username='user', password='user123')
        
        # 创建一个待删除的用户
        user_to_delete = User.objects.create_user(
            username='todelete',
            password='delete123'
        )
        
        response = self.client.post('/admins/subpages/delete-user/', {
            'user_id': user_to_delete.id
        })
        
        # 验证是否返回403错误
        self.assertEqual(response.status_code, 403)
        # 验证用户是否未被删除
        self.assertTrue(User.objects.filter(username='todelete').exists())
    
    def test_user_cannot_delete_self(self):
        """测试用户不能删除自己"""
        self.client.login(username='admin', password='admin123')
        
        response = self.client.post('/admins/subpages/delete-user/', {
            'user_id': self.super_admin.id
        })
        
        # 验证是否返回错误
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        # 验证用户是否未被删除
        self.assertTrue(User.objects.filter(username='admin').exists())
    
    def test_user_cannot_disable_self(self):
        """测试用户不能禁用自己"""
        self.client.login(username='admin', password='admin123')
        
        response = self.client.post('/admins/subpages/user-form/', {
            'user_id': self.super_admin.id,
            'username': 'admin',
            'is_active': 'off'
        })
        
        # 验证是否返回错误
        self.assertEqual(response.status_code, 200)
        self.assertIn('error', response.context)
        # 验证用户是否未被禁用
        self.super_admin.refresh_from_db()
        self.assertTrue(self.super_admin.is_active)


class PermissionAuditLogTestCase(PermissionControlTestCase):
    """权限审计日志测试用例"""
    
    def test_audit_log_created_on_user_creation(self):
        """测试创建用户时是否生成审计日志"""
        self.client.login(username='admin', password='admin123')
        
        initial_log_count = PermissionAuditLog.objects.count()
        
        self.client.post('/admins/subpages/user-form/', {
            'username': 'newuser',
            'password1': 'newuser123',
            'password2': 'newuser123'
        })
        
        # 验证是否生成了审计日志
        self.assertEqual(
            PermissionAuditLog.objects.count(),
            initial_log_count + 1
        )
        
        # 验证审计日志的内容
        log = PermissionAuditLog.objects.filter(
            action='CREATE_USER'
        ).first()
        self.assertIsNotNone(log)
        self.assertEqual(log.user, self.super_admin)
        self.assertEqual(log.status, 'SUCCESS')
    
    def test_audit_log_created_on_user_deletion(self):
        """测试删除用户时是否生成审计日志"""
        self.client.login(username='admin', password='admin123')
        
        user_to_delete = User.objects.create_user(
            username='todelete',
            password='delete123'
        )
        
        initial_log_count = PermissionAuditLog.objects.count()
        
        self.client.post('/admins/subpages/delete-user/', {
            'user_id': user_to_delete.id
        })
        
        # 验证是否生成了审计日志（包括装饰器的访问日志和删除操作日志）
        self.assertEqual(
            PermissionAuditLog.objects.count(),
            initial_log_count + 2  # ACCESS_ADMIN (装饰器) + DELETE_USER (视图)
        )
        
        # 验证审计日志的内容
        log = PermissionAuditLog.objects.filter(
            action='DELETE_USER'
        ).first()
        self.assertIsNotNone(log)
        self.assertEqual(log.user, self.super_admin)
        self.assertEqual(log.status, 'SUCCESS')
    
    def test_audit_log_on_permission_denied(self):
        """测试权限被拒绝时是否生成审计日志"""
        self.client.login(username='user', password='user123')
        
        initial_log_count = PermissionAuditLog.objects.count()
        
        self.client.get('/admins/')
        
        # 验证是否生成了审计日志
        self.assertEqual(
            PermissionAuditLog.objects.count(),
            initial_log_count + 1
        )
        
        # 验证审计日志的内容
        log = PermissionAuditLog.objects.filter(
            action='ACCESS_ADMIN',
            status='DENIED'
        ).first()
        self.assertIsNotNone(log)
        self.assertEqual(log.user, self.normal_user)
    
    def test_audit_log_details(self):
        """测试审计日志的详细信息"""
        self.client.login(username='admin', password='admin123')
        
        self.client.post('/admins/subpages/user-form/', {
            'username': 'newuser',
            'is_staff': 'on',
            'is_superuser': 'off',
            'password1': 'newuser123',
            'password2': 'newuser123'
        })
        
        log = PermissionAuditLog.objects.filter(
            action='CREATE_USER'
        ).first()
        
        # 验证详细信息
        self.assertIsNotNone(log.details)
        self.assertIn('username', log.details)
        self.assertEqual(log.details['username'], 'newuser')
        self.assertIn('is_staff', log.details)
        self.assertTrue(log.details['is_staff'])
    
    def test_audit_log_ip_address(self):
        """测试审计日志是否记录IP地址"""
        self.client.login(username='admin', password='admin123')
        
        self.client.post('/admins/subpages/user-form/', {
            'username': 'newuser',
            'password1': 'newuser123',
            'password2': 'newuser123'
        })
        
        log = PermissionAuditLog.objects.filter(
            action='CREATE_USER'
        ).first()
        
        # 验证IP地址是否被记录
        self.assertIsNotNone(log.ip_address)


class PermissionHelperFunctionTestCase(PermissionControlTestCase):
    """权限辅助函数测试用例"""
    
    def test_is_super_admin_with_admin(self):
        """测试is_super_admin函数对管理员用户"""
        self.assertTrue(is_super_admin(self.super_admin))
    
    def test_is_super_admin_with_normal_user(self):
        """测试is_super_admin函数对普通用户"""
        self.assertFalse(is_super_admin(self.normal_user))
    
    def test_is_super_admin_with_anonymous(self):
        """测试is_super_admin函数对匿名用户"""
        from django.contrib.auth.models import AnonymousUser
        anonymous_user = AnonymousUser()
        self.assertFalse(is_super_admin(anonymous_user))
    
    def test_log_permission_audit(self):
        """测试log_permission_audit函数"""
        from django.test import RequestFactory
        factory = RequestFactory()
        request = factory.get('/test/')
        request.user = self.super_admin
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        request.META['HTTP_USER_AGENT'] = 'Test Agent'
        
        initial_log_count = PermissionAuditLog.objects.count()
        
        log_permission_audit(
            user=self.super_admin,
            action='TEST_ACTION',
            status='SUCCESS',
            request=request,
            details={'test': 'data'}
        )
        
        # 验证是否生成了审计日志
        self.assertEqual(
            PermissionAuditLog.objects.count(),
            initial_log_count + 1
        )
        
        log = PermissionAuditLog.objects.filter(
            action='TEST_ACTION'
        ).first()
        self.assertIsNotNone(log)
        self.assertEqual(log.user, self.super_admin)
        self.assertEqual(log.status, 'SUCCESS')
        self.assertEqual(log.ip_address, '127.0.0.1')


class SecurityEdgeCaseTestCase(PermissionControlTestCase):
    """安全边界情况测试用例"""
    
    def test_multiple_super_admins_creation(self):
        """测试创建多个超级管理员"""
        self.client.login(username='admin', password='admin123')
        
        # 尝试创建第二个超级管理员
        response = self.client.post('/admins/subpages/user-form/', {
            'username': 'admin2',
            'is_superuser': 'on',
            'is_staff': 'on',
            'password1': 'admin2123',
            'password2': 'admin2123'
        })
        
        # 验证是否创建成功
        self.assertTrue(User.objects.filter(username='admin2').exists())
        admin2 = User.objects.get(username='admin2')
        self.assertTrue(admin2.is_superuser)
    
    def test_password_mismatch_handling(self):
        """测试密码不匹配的处理"""
        self.client.login(username='admin', password='admin123')
        
        response = self.client.post('/admins/subpages/user-form/', {
            'username': 'newuser',
            'password1': 'password1',
            'password2': 'password2'
        })
        
        # 验证是否返回错误
        self.assertEqual(response.status_code, 200)
        self.assertIn('error', response.context)
        # 验证用户是否未被创建
        self.assertFalse(User.objects.filter(username='newuser').exists())
    
    def test_empty_password_handling(self):
        """测试空密码的处理"""
        self.client.login(username='admin', password='admin123')
        
        response = self.client.post('/admins/subpages/user-form/', {
            'username': 'newuser',
            'password1': '',
            'password2': ''
        })
        
        # 验证是否返回错误
        self.assertEqual(response.status_code, 200)
        self.assertIn('error', response.context)
        # 验证用户是否未被创建
        self.assertFalse(User.objects.filter(username='newuser').exists())
    
    def test_duplicate_username_handling(self):
        """测试重复用户名的处理"""
        self.client.login(username='admin', password='admin123')
        
        response = self.client.post('/admins/subpages/user-form/', {
            'username': 'user',  # 已存在的用户名
            'password1': 'newpass123',
            'password2': 'newpass123'
        })
        
        # 验证是否返回错误
        self.assertEqual(response.status_code, 200)
        self.assertIn('error', response.context)


class PermissionIntegrationTestCase(PermissionControlTestCase):
    """权限集成测试用例"""
    
    def test_complete_user_lifecycle(self):
        """测试完整的用户生命周期"""
        self.client.login(username='admin', password='admin123')
        
        # 1. 创建用户
        response = self.client.post('/admins/subpages/user-form/', {
            'username': 'lifecycle',
            'password1': 'lifecycle123',
            'password2': 'lifecycle123'
        })
        self.assertTrue(User.objects.filter(username='lifecycle').exists())
        
        # 2. 更新用户
        user = User.objects.get(username='lifecycle')
        response = self.client.post('/admins/subpages/user-form/', {
            'user_id': user.id,
            'username': 'lifecycle',
            'first_name': 'Test',
            'is_staff': 'on'
        })
        user.refresh_from_db()
        self.assertEqual(user.first_name, 'Test')
        self.assertTrue(user.is_staff)
        
        # 3. 删除用户
        response = self.client.post('/admins/subpages/delete-user/', {
            'user_id': user.id
        })
        self.assertFalse(User.objects.filter(username='lifecycle').exists())
        
        # 4. 验证审计日志
        # 查找创建和更新用户的日志（通过target_user）
        create_update_logs = PermissionAuditLog.objects.filter(
            action__in=['CREATE_USER', 'UPDATE_USER'],
            details__username='lifecycle'
        )
        self.assertEqual(create_update_logs.count(), 2)  # CREATE, UPDATE
        
        # 查找删除用户的日志（通过details字段，因为用户已被删除）
        delete_logs = PermissionAuditLog.objects.filter(
            action='DELETE_USER',
            details__deleted_username='lifecycle'
        )
        self.assertEqual(delete_logs.count(), 1)  # DELETE
    
    def test_permission_denied_audit_trail(self):
        """测试权限被拒绝的审计轨迹"""
        self.client.login(username='user', password='user123')
        
        # 尝试访问管理页面
        self.client.get('/admins/')
        
        # 尝试创建用户
        self.client.post('/admins/subpages/user-form/', {
            'username': 'newuser',
            'password1': 'newuser123',
            'password2': 'newuser123'
        })
        
        # 尝试删除用户
        self.client.post('/admins/subpages/delete-user/', {
            'user_id': self.super_admin.id
        })
        
        # 验证所有操作都被记录为DENIED
        denied_logs = PermissionAuditLog.objects.filter(
            user=self.normal_user,
            status='DENIED'
        )
        self.assertGreaterEqual(denied_logs.count(), 3)