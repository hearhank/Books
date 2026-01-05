from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.core.paginator import Paginator
from .models import Article, Book, PermissionAuditLog, SystemConfig
from .forms import ArticleForm, BookForm
from .permissions import (
    super_admin_required, staff_required, first_user_or_super_admin,
    log_permission_audit, get_client_ip, is_first_user
)
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib import messages

def user_login(request):
    """用户登录视图函数"""
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        # 验证用户名和密码
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            # 登录成功
            login(request, user)
            
            # 记录审计日志
            log_permission_audit(
                user=user,
                action='LOGIN',
                status='SUCCESS',
                request=request,
                details={'username': username}
            )
            
            # 获取next参数，如果存在则重定向到指定页面
            next_url = request.POST.get('next') or request.GET.get('next')
            if next_url:
                return redirect(next_url)
            return redirect('admins')
        else:
            # 登录失败
            log_permission_audit(
                user=None,
                action='LOGIN',
                status='FAILED',
                request=request,
                details={
                    'username': username,
                    'reason': 'invalid_credentials'
                }
            )
            
            context = {
                'error': '用户名或密码错误'
            }
            return render(request, 'mdsource/login.html', context)
    
    return render(request, 'mdsource/login.html')

def user_logout(request):
    """用户登出视图函数"""
    if request.user.is_authenticated:
        # 记录审计日志
        log_permission_audit(
            user=request.user,
            action='LOGOUT',
            status='SUCCESS',
            request=request
        )
        # 执行登出
        logout(request)
    
    # 重定向到首页
    return redirect('index')

@login_required
def change_password(request):
    """修改密码视图函数"""
    if request.method == 'POST':
        form = PasswordChangeForm(user=request.user, data=request.POST)
        if form.is_valid():
            user = form.save()
            # 更新会话，保持用户登录状态
            update_session_auth_hash(request, user)
            
            # 记录审计日志
            log_permission_audit(
                user=request.user,
                action='CHANGE_PASSWORD',
                status='SUCCESS',
                request=request
            )
            
            messages.success(request, '密码修改成功！')
            return redirect('admins')
        else:
            # 记录审计日志
            log_permission_audit(
                user=request.user,
                action='CHANGE_PASSWORD',
                status='FAILED',
                request=request,
                details={'errors': form.errors.get_json_data()}
            )
    else:
        form = PasswordChangeForm(user=request.user)
    
    return render(request, 'mdsource/change_password.html', {'form': form})

def article_list(request):
    articles = Article.objects.all().order_by('-pub_date')
    return render(request, 'mdsource/article_list.html', {'articles': articles})

def article_detail(request, article_id):
    article = get_object_or_404(Article, pk=article_id)
    return render(request, 'mdsource/article_detail.html', {'article': article})

def book_create(request):
    if request.method == 'POST':
        form = BookForm(request.POST, request.FILES)
        if form.is_valid():
            book = form.save(commit=False)
            book.user = request.user
            book.save()
            return redirect('book_detail', book_id=book.id)
    else:
        form = BookForm()
    return render(request, 'mdsource/book_form.html', {'form': form, 'title': '创建书籍'})

def article_create(request):
    if request.method == 'POST':
        form = ArticleForm(request.POST, user=request.user)
        if form.is_valid():
            article = form.save()
            return redirect('article_detail', article_id=article.id)
    else:
        # 获取URL中的book_id参数
        book_id = request.GET.get('book_id')
        initial_data = {}
        
        # 如果有book_id参数，设置默认选中的书籍
        if book_id:
            try:
                book = Book.objects.get(pk=book_id)
                initial_data['book'] = book
            except Book.DoesNotExist:
                pass
        
        form = ArticleForm(user=request.user, initial=initial_data)
    
    return render(request, 'mdsource/article_form.html', {'form': form, 'title': '创建文章'})

def article_edit(request, article_id):
    article = get_object_or_404(Article, pk=article_id)
    if request.method == 'POST':
        form = ArticleForm(request.POST, instance=article, user=request.user)
        if form.is_valid():
            article = form.save()
            return redirect('article_detail', article_id=article.id)
    else:
        form = ArticleForm(instance=article, user=request.user)
    return render(request, 'mdsource/article_form.html', {'form': form, 'title': '编辑文章'})

def book_edit(request, book_id):
    book = get_object_or_404(Book, pk=book_id)
    if request.method == 'POST':
        form = BookForm(request.POST, request.FILES, instance=book)
        if form.is_valid():
            book = form.save()
            return redirect('book_detail', book_id=book.id)
    else:
        form = BookForm(instance=book)
    return render(request, 'mdsource/book_form.html', {'form': form, 'title': '编辑书籍'})

def article_content(request, article_id):
    """返回文章内容的JSON数据，用于AJAX请求"""
    article = get_object_or_404(Article, pk=article_id)
    return JsonResponse({
        'id': article.id,
        'title': article.title,
        'pub_date': article.pub_date.strftime('%Y-%m-%d %H:%M:%S'),
        'content': article.get_markdown_content()
    })

def toggle_book_published(request, book_id):
    """切换书籍的发布状态"""
    if request.method == 'POST':
        book = get_object_or_404(Book, pk=book_id)
        book.is_published = not book.is_published
        book.save()
        return JsonResponse({
            'success': True,
            'is_published': book.is_published,
            'status_text': '已发布' if book.is_published else '未发布'
        })
    return JsonResponse({'success': False, 'error': 'Invalid request method'}, status=400)

def book_detail(request, book_id):
    book = get_object_or_404(Book, pk=book_id)
    articles = book.articles.all().order_by('-pub_date')
    return render(request, 'mdsource/book_detail.html', {'book': book, 'articles': articles})

def index(request):
    """首页视图函数，实现简化的搜索和分页功能"""
    from django.db.models import Q
    
    # 获取搜索参数
    query = request.GET.get('q', '').strip()
    page = request.GET.get('page', 1)
    page_size = request.GET.get('page_size', '10')
    
    # 构建查询
    books = Book.objects.all()
    
    if not query:
        # 搜索框为空，按时间倒序排列
        books = books.order_by('-pub_date')
    elif ':' in query or '：' in query:
        # 包含冒号，按冒号分隔为作者和标题
        # 使用正则表达式处理多个连续冒号或全角冒号
        import re
        parts = re.split(r'[:：]+', query, maxsplit=1)
        author = parts[0].strip() if len(parts) > 0 else ''
        title = parts[1].strip() if len(parts) > 1 else ''
        
        if author and title:
            # 同时满足作者和标题
            books = books.filter(Q(author__icontains=author) & Q(title__icontains=title)).order_by('-pub_date')
        elif author:
            # 只有作者，按作者搜索
            books = books.filter(author__icontains=author).order_by('-pub_date')
        elif title:
            # 只有标题，按标题搜索
            books = books.filter(title__icontains=title).order_by('-pub_date')
    else:
        # 其他情况，模糊搜索标题、作者和内容
        books = books.filter(
            Q(title__icontains=query) | 
            Q(author__icontains=query) | 
            Q(description__icontains=query)
        ).order_by('-pub_date')
    
    # 使用用户选择的每页显示数量
    paginator = Paginator(books, int(page_size))
    page_obj = paginator.get_page(page)
    
    context = {
        'page_obj': page_obj,
        'books': page_obj.object_list,
        'query': query,
        'total_books': books.count(),
        'page_size': page_size
    }
    
    return render(request, 'mdsource/index.html', context)


@super_admin_required
def admins(request):
    """自定义管理页面视图函数"""
    # 获取所有模型数据
    from django.contrib.auth.models import User, Group
    from django.core.paginator import Paginator
    
    # 每页显示数量
    per_page = 10
    
    # 用户数据分页
    users_list = User.objects.all().order_by('id')
    paginator_users = Paginator(users_list, per_page)
    page_users = request.GET.get('page_users', 1)
    users = paginator_users.get_page(page_users)
    
    # 用户组数据分页
    groups_list = Group.objects.all().order_by('id')
    paginator_groups = Paginator(groups_list, per_page)
    page_groups = request.GET.get('page_groups', 1)
    groups = paginator_groups.get_page(page_groups)
    
    # 书籍数据分页
    books_list = Book.objects.all().order_by('is_published', '-pub_date', 'title')
    paginator_books = Paginator(books_list, per_page)
    page_books = request.GET.get('page_books', 1)
    books = paginator_books.get_page(page_books)
    
    # 文章数据分页
    articles_list = Article.objects.all().order_by('id')
    paginator_articles = Paginator(articles_list, per_page)
    page_articles = request.GET.get('page_articles', 1)
    articles = paginator_articles.get_page(page_articles)
    
    # 获取当前登录用户
    current_user = request.user
    
    context = {
        'current_user': current_user,
        'users': users,
        'groups': groups,
        'books': books,
        'articles': articles,
        'per_page': per_page
    }
    
    return render(request, 'mdsource/admins.html', context)


def user_form(request):
    """用户表单视图函数，处理用户的创建和编辑"""
    from django.contrib.auth.models import User
    from django.contrib.auth.hashers import make_password
    
    user_id = request.POST.get('user_id') or request.GET.get('user_id')
    current_user = request.user
    context = {}
    
    # 检查登录状态：
    # 1. 如果是创建用户且当前没有超级管理员（第一个用户），允许未登录用户访问
    # 2. 其他情况要求用户已登录
    if not user_id and is_first_user():
        # 第一个用户创建场景，允许未登录用户访问
        pass
    elif not request.user.is_authenticated:
        # 未登录用户访问非第一个用户创建场景，重定向到登录页面
        from django.contrib.auth.decorators import login_required
        return login_required(lambda r: r)(request)
    
    # 检查权限：
    # 1. 如果是创建用户且当前没有超级管理员（第一个用户），允许访问
    # 2. 其他情况要求超级管理员权限
    if not user_id and is_first_user():
        # 第一个用户创建场景，允许访问
        pass
    elif not current_user.is_superuser:
        log_permission_audit(
            user=current_user,
            action='CREATE_USER' if not user_id else 'UPDATE_USER',
            status='DENIED',
            request=request,
            details={'user_id': user_id}
        )
        return JsonResponse({
            'success': False,
            'error': '只有超级管理员才能创建或编辑用户'
        }, status=403)
    
    # 获取用户对象（无论是GET还是POST请求）
    if user_id:
        # 编辑用户
        user = get_object_or_404(User, pk=user_id)
        context['user'] = user
        context['title'] = '编辑用户'
    else:
        # 创建用户
        context['user'] = None  # 明确设置为None，避免模板中访问不存在的属性
        context['title'] = '创建用户'
    
    if request.method == 'POST':
        try:
            username = request.POST.get('username', '').strip()
            first_name = request.POST.get('first_name', '').strip()
            last_name = request.POST.get('last_name', '').strip()
            email = request.POST.get('email', '').strip()
            
            # 处理复选框值，当用户未修改时保留原来的值
            if user_id:
                user = get_object_or_404(User, pk=user_id)
                is_active = request.POST.get('is_active') == 'on' if 'is_active' in request.POST else user.is_active
                is_staff = request.POST.get('is_staff') == 'on' if 'is_staff' in request.POST else user.is_staff
                is_superuser = request.POST.get('is_superuser') == 'on' if 'is_superuser' in request.POST else user.is_superuser
            else:
                # 创建新用户时的权限逻辑
                # 检查是否是第一个用户
                if is_first_user():
                    # 第一个用户自动获得超级管理员权限
                    is_active = True
                    is_staff = True
                    is_superuser = True
                else:
                    # 后续用户默认为普通用户
                    is_active = request.POST.get('is_active') == 'on' if 'is_active' in request.POST else True
                    is_staff = request.POST.get('is_staff') == 'on' if 'is_staff' in request.POST else False
                    is_superuser = request.POST.get('is_superuser') == 'on' if 'is_superuser' in request.POST else False
            
            print(is_active, is_staff, is_superuser)
            # 检查是否是当前用户尝试禁用自己
            if user_id and int(user_id) == current_user.id:
                if not is_active:
                    # 不允许禁用自己的账户
                    context['error'] = '您不能禁用自己的账户'
                    # 确保用户对象在错误情况下仍然存在于context中
                    if 'user' not in context:
                        context['user'] = get_object_or_404(User, pk=user_id)
                    log_permission_audit(
                        user=current_user,
                        action='UPDATE_USER',
                        status='FAILED',
                        target_user=user,
                        request=request,
                        details={'reason': 'attempted to disable own account'}
                    )
                    return render(request, 'mdsource/subpages/user_form.html', context)
            
            if user_id:
                # 更新现有用户
                user = get_object_or_404(User, pk=user_id)
                user.username = username
                user.first_name = first_name
                user.last_name = last_name
                user.email = email
                user.is_active = is_active
                user.is_staff = is_staff
                user.is_superuser = is_superuser
                
                # 如果提供了密码则更新密码
                password1 = request.POST.get('password1')
                password2 = request.POST.get('password2')
                if password1 and password2 and password1 == password2:
                    user.password = make_password(password1)
                elif password1 or password2:
                    # 密码不匹配或只提供了一个密码
                    context['error'] = '两次输入的密码不一致'
                    # 确保用户对象在错误情况下仍然存在于context中
                    context['user'] = user
                    # 将表单数据传递回模板，以便用户不需要重新填写所有字段
                    context['form_data'] = {
                        'username': username,
                        'first_name': first_name,
                        'last_name': last_name,
                        'email': email,
                        'is_active': is_active,
                        'is_staff': is_staff,
                        'is_superuser': is_superuser
                    }
                    log_permission_audit(
                        user=current_user,
                        action='UPDATE_USER',
                        status='FAILED',
                        target_user=user,
                        request=request,
                        details={'reason': 'password mismatch'}
                    )
                    return render(request, 'mdsource/subpages/user_form.html', context)
                
                user.save()
                
                # 记录审计日志
                log_permission_audit(
                    user=current_user,
                    action='UPDATE_USER',
                    status='SUCCESS',
                    target_user=user,
                    request=request,
                    details={
                        'username': username,
                        'is_active': is_active,
                        'is_staff': is_staff,
                        'is_superuser': is_superuser
                    }
                )
            else:
                # 检查用户名是否已存在
                if User.objects.filter(username=username).exists():
                    context['error'] = f'用户名 "{username}" 已存在'
                    # 将表单数据传递回模板，以便用户不需要重新填写所有字段
                    context['form_data'] = {
                        'username': username,
                        'first_name': first_name,
                        'last_name': last_name,
                        'email': email,
                        'is_active': is_active,
                        'is_staff': is_staff,
                        'is_superuser': is_superuser
                    }
                    log_permission_audit(
                        user=current_user,
                        action='CREATE_USER',
                        status='FAILED',
                        request=request,
                        details={'reason': 'username already exists', 'username': username}
                    )
                    return render(request, 'mdsource/subpages/user_form.html', context)
                
                # 创建新用户
                password1 = request.POST.get('password1')
                password2 = request.POST.get('password2')
                
                if not password1 or not password2:
                    context['error'] = '密码不能为空'
                    # 将表单数据传递回模板，以便用户不需要重新填写所有字段
                    context['form_data'] = {
                        'username': username,
                        'first_name': first_name,
                        'last_name': last_name,
                        'email': email,
                        'is_active': is_active,
                        'is_staff': is_staff,
                        'is_superuser': is_superuser
                    }
                    log_permission_audit(
                        user=current_user,
                        action='CREATE_USER',
                        status='FAILED',
                        request=request,
                        details={'reason': 'password missing', 'username': username}
                    )
                    return render(request, 'mdsource/subpages/user_form.html', context)
                
                if password1 != password2:
                    context['error'] = '两次输入的密码不一致'
                    # 将表单数据传递回模板，以便用户不需要重新填写所有字段
                    context['form_data'] = {
                        'username': username,
                        'first_name': first_name,
                        'last_name': last_name,
                        'email': email,
                        'is_active': is_active,
                        'is_staff': is_staff,
                        'is_superuser': is_superuser
                    }
                    log_permission_audit(
                        user=current_user,
                        action='CREATE_USER',
                        status='FAILED',
                        request=request,
                        details={'reason': 'password mismatch', 'username': username}
                    )
                    return render(request, 'mdsource/subpages/user_form.html', context)
                
                # 创建新用户
                # 在创建用户之前检查是否是第一个用户
                was_first_user = is_first_user()
                user = User.objects.create(
                    username=username,
                    first_name=first_name,
                    last_name=last_name,
                    email=email,
                    password=make_password(password1),
                    is_active=is_active,
                    is_staff=is_staff,
                    is_superuser=is_superuser
                )
                
                # 记录审计日志
                # 如果是第一个用户创建场景，使用新创建的用户作为审计日志的user
                audit_user = user if was_first_user else current_user
                log_permission_audit(
                    user=audit_user,
                    action='CREATE_USER',
                    status='SUCCESS',
                    target_user=user,
                    request=request,
                    details={
                        'username': username,
                        'is_active': is_active,
                        'is_staff': is_staff,
                        'is_superuser': is_superuser,
                        'is_first_user': was_first_user
                    }
                )
                
            # 重定向到用户列表
            return redirect('/admins/subpages/users/')
        except Exception as e:
            context['error'] = str(e)
            # 确保用户对象在错误情况下仍然存在于context中
            if user_id and 'user' not in context:
                context['user'] = get_object_or_404(User, pk=user_id)
            
            log_permission_audit(
                user=current_user,
                action='CREATE_USER' if not user_id else 'UPDATE_USER',
                status='FAILED',
                request=request,
                details={'error': str(e), 'username': username if 'username' in locals() else None}
            )
    
    return render(request, 'mdsource/subpages/user_form.html', context)


@super_admin_required
def delete_user(request):
    """删除用户的视图函数，确保用户不能删除自己"""
    from django.contrib.auth.models import User
    from django.http import JsonResponse
    import json
    
    if request.method == 'POST':
        try:
            # 尝试从JSON数据中获取user_id
            data = json.loads(request.body)
            user_id = data.get('user_id')
        except (json.JSONDecodeError, AttributeError):
            # 如果不是JSON,尝试从表单数据中获取
            user_id = request.POST.get('user_id')
        
        current_user = request.user
        
        try:
            # 检查是否是当前用户尝试删除自己
            if int(user_id) == current_user.id:
                log_permission_audit(
                    user=current_user,
                    action='DELETE_USER',
                    status='FAILED',
                    target_user=current_user,
                    request=request,
                    details={'reason': 'attempted to delete own account'}
                )
                return JsonResponse({'success': False, 'error': '您不能删除自己的账户'})
            
            # 执行删除操作
            user = get_object_or_404(User, pk=user_id)
            
            # 在删除之前保存用户信息，用于审计日志
            user_info = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_staff': user.is_staff,
                'is_superuser': user.is_superuser
            }
            
            user.delete()
            
            # 记录审计日志（使用保存的用户信息，因为用户已被删除）
            log_permission_audit(
                user=current_user,
                action='DELETE_USER',
                status='SUCCESS',
                target_user=None,  # 用户已被删除，无法设置target_user
                request=request,
                details={
                    'deleted_username': user_info['username'],
                    'deleted_user_id': user_info['id'],
                    'deleted_user_email': user_info['email'],
                    'deleted_user_is_staff': user_info['is_staff'],
                    'deleted_user_is_superuser': user_info['is_superuser']
                }
            )
            
            return JsonResponse({'success': True, 'message': '用户已成功删除'})
        except Exception as e:
            log_permission_audit(
                user=current_user,
                action='DELETE_USER',
                status='FAILED',
                request=request,
                details={'error': str(e), 'user_id': user_id}
            )
            return JsonResponse({'success': False, 'error': str(e)})
    
    return JsonResponse({'success': False, 'error': 'Invalid request method'}, status=400)


@super_admin_required
def delete_book(request):
    """删除书籍的视图函数"""
    from django.http import JsonResponse
    import json
    
    if request.method == 'POST':
        try:
            # 尝试从JSON数据中获取book_id
            data = json.loads(request.body)
            book_id = data.get('book_id')
        except (json.JSONDecodeError, AttributeError):
            # 如果不是JSON,尝试从表单数据中获取
            book_id = request.POST.get('book_id')
        
        current_user = request.user
        
        try:
            # 获取书籍对象
            book = get_object_or_404(Book, pk=book_id)
            
            # 检查书籍是否有文章
            article_count = book.articles.count()
            if article_count > 0:
                log_permission_audit(
                    user=current_user,
                    action='DELETE_BOOK',
                    status='FAILED',
                    request=request,
                    details={
                        'book_id': book_id,
                        'book_title': book.title,
                        'reason': 'book has articles',
                        'article_count': article_count
                    }
                )
                return JsonResponse({
                    'success': False,
                    'error': f'该书籍下还有 {article_count} 篇文章，无法删除。请先删除所有文章后再删除书籍。'
                })
            
            # 在删除之前保存书籍信息，用于审计日志
            book_info = {
                'id': book.id,
                'title': book.title,
                'author': book.author,
                'is_published': book.is_published,
                'pub_date': book.pub_date.strftime('%Y-%m-%d %H:%M:%S') if book.pub_date else None
            }
            
            # 执行删除操作
            book.delete()
            
            # 记录审计日志
            log_permission_audit(
                user=current_user,
                action='DELETE_BOOK',
                status='SUCCESS',
                request=request,
                details={
                    'deleted_book_id': book_info['id'],
                    'deleted_book_title': book_info['title'],
                    'deleted_book_author': book_info['author'],
                    'deleted_book_is_published': book_info['is_published'],
                    'deleted_book_pub_date': book_info['pub_date']
                }
            )
            
            return JsonResponse({'success': True, 'message': '书籍已成功删除'})
        except Exception as e:
            log_permission_audit(
                user=current_user,
                action='DELETE_BOOK',
                status='FAILED',
                request=request,
                details={'error': str(e), 'book_id': book_id}
            )
            return JsonResponse({'success': False, 'error': str(e)})
    
    return JsonResponse({'success': False, 'error': 'Invalid request method'}, status=400)


@super_admin_required
def delete_article(request):
    """删除文章的视图函数"""
    from django.http import JsonResponse
    import json
    
    if request.method == 'POST':
        try:
            # 尝试从JSON数据中获取article_id
            data = json.loads(request.body)
            article_id = data.get('article_id')
        except (json.JSONDecodeError, AttributeError):
            # 如果不是JSON,尝试从表单数据中获取
            article_id = request.POST.get('article_id')
        
        current_user = request.user
        
        try:
            # 获取文章对象
            article = get_object_or_404(Article, pk=article_id)
            
            # 在删除之前保存文章信息，用于审计日志
            article_info = {
                'id': article.id,
                'title': article.title,
                'book_id': article.book.id if article.book else None,
                'book_title': article.book.title if article.book else None,
                'pub_date': article.pub_date.strftime('%Y-%m-%d %H:%M:%S') if article.pub_date else None
            }
            
            # 执行删除操作
            article.delete()
            
            # 记录审计日志
            log_permission_audit(
                user=current_user,
                action='DELETE_ARTICLE',
                status='SUCCESS',
                request=request,
                details={
                    'deleted_article_id': article_info['id'],
                    'deleted_article_title': article_info['title'],
                    'deleted_book_id': article_info['book_id'],
                    'deleted_book_title': article_info['book_title'],
                    'deleted_article_pub_date': article_info['pub_date']
                }
            )
            
            return JsonResponse({'success': True, 'message': '文章已成功删除'})
        except Exception as e:
            log_permission_audit(
                user=current_user,
                action='DELETE_ARTICLE',
                status='FAILED',
                request=request,
                details={'error': str(e), 'article_id': article_id}
            )
            return JsonResponse({'success': False, 'error': str(e)})
    
    return JsonResponse({'success': False, 'error': 'Invalid request method'}, status=400)


@super_admin_required
def subpage_loader(request, module_name):
    """子页面加载器，根据模块名称加载对应的子页面内容"""
    from django.core.paginator import Paginator
    from django.contrib.auth.models import User, Group
    
    per_page = 10
    context = {}
    
    if module_name == 'users':
        # 用户数据分页
        users_list = User.objects.all().order_by('id')
        paginator_users = Paginator(users_list, per_page)
        page_users = request.GET.get('page_users', 1)
        context['users'] = paginator_users.get_page(page_users)
        template_name = 'mdsource/subpages/users.html'
        
    elif module_name == 'groups':
        # 用户组数据分页
        groups_list = Group.objects.all().order_by('id')
        paginator_groups = Paginator(groups_list, per_page)
        page_groups = request.GET.get('page_groups', 1)
        context['groups'] = paginator_groups.get_page(page_groups)
        template_name = 'mdsource/subpages/groups.html'
        
    elif module_name == 'books':
        # 书籍数据分页
        books_list = Book.objects.all().order_by('is_published', '-pub_date', 'title')
        paginator_books = Paginator(books_list, per_page)
        page_books = request.GET.get('page_books', 1)
        context['books'] = paginator_books.get_page(page_books)
        template_name = 'mdsource/subpages/books.html'
        
    elif module_name == 'articles':
        # 文章数据分页
        articles_list = Article.objects.all().order_by('id')
        paginator_articles = Paginator(articles_list, per_page)
        page_articles = request.GET.get('page_articles', 1)
        context['articles'] = paginator_articles.get_page(page_articles)
        template_name = 'mdsource/subpages/articles.html'
        
    elif module_name == 'logs':
        # 日志数据分页
        logs_list = PermissionAuditLog.objects.all().order_by('-timestamp')
        paginator_logs = Paginator(logs_list, per_page)
        page_logs = request.GET.get('page_logs', 1)
        context['logs'] = paginator_logs.get_page(page_logs)
        template_name = 'mdsource/subpages/logs.html'
        
    else:
        # 默认返回用户管理页面
        users_list = User.objects.all().order_by('id')
        paginator_users = Paginator(users_list, per_page)
        page_users = request.GET.get('page_users', 1)
        context['users'] = paginator_users.get_page(page_users)
        template_name = 'mdsource/subpages/users.html'
    
    return render(request, template_name, context)


@super_admin_required
def audit_logs(request):
    """审计日志列表视图函数"""
    from django.core.paginator import Paginator
    
    # 获取查询参数
    action_filter = request.GET.get('action', '')
    status_filter = request.GET.get('status', '')
    start_date = request.GET.get('start_date', '')
    end_date = request.GET.get('end_date', '')
    
    # 获取所有日志并按时间倒序排列
    logs = PermissionAuditLog.objects.all().order_by('-timestamp')
    
    # 应用筛选条件
    if action_filter:
        logs = logs.filter(action=action_filter)
    if status_filter:
        logs = logs.filter(status=status_filter)
    if start_date:
        logs = logs.filter(timestamp__gte=start_date)
    if end_date:
        logs = logs.filter(timestamp__lte=end_date)
    
    # 分页
    per_page = 20
    paginator = Paginator(logs, per_page)
    page = request.GET.get('page', 1)
    logs_page = paginator.get_page(page)
    
    # 获取所有可用的操作类型和状态
    available_actions = PermissionAuditLog.objects.values_list('action', flat=True).distinct()
    available_statuses = PermissionAuditLog.objects.values_list('status', flat=True).distinct()
    
    context = {
        'logs': logs_page,
        'available_actions': available_actions,
        'available_statuses': available_statuses,
        'action_filter': action_filter,
        'status_filter': status_filter,
        'start_date': start_date,
        'end_date': end_date,
        'current_user': request.user
    }
    
    return render(request, 'mdsource/subpages/logs.html', context)