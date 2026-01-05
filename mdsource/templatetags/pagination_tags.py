from django import template

register = template.Library()


@register.simple_tag
def smart_page_range(page, num_links=7):
    """
    智能分页标签，当页数较多时显示省略号
    
    参数:
        page: 当前页面对象
        num_links: 显示的页码链接数量（默认为7）
    
    返回:
        页码列表，包含页码数字或None（表示省略号）
    """
    current = page.number
    total = page.paginator.num_pages
    
    if total <= num_links:
        # 总页数小于等于显示数量，显示所有页码
        return range(1, total + 1)
    
    # 计算显示的页码范围
    half_links = (num_links - 1) // 2
    start = max(1, current - half_links)
    end = min(total, current + half_links)
    
    # 调整范围以确保显示足够数量的页码
    if end - start < num_links - 1:
        if start == 1:
            end = min(total, start + num_links - 1)
        elif end == total:
            start = max(1, end - num_links + 1)
    
    # 生成页码列表
    pages = []
    for i in range(start, end + 1):
        pages.append(i)
    
    # 在开头添加省略号和第一页
    if start > 1:
        if start > 2:
            pages.insert(0, None)  # 添加省略号
        pages.insert(0, 1)  # 添加第一页
    
    # 在末尾添加省略号和最后一页
    if end < total:
        if end < total - 1:
            pages.append(None)  # 添加省略号
        pages.append(total)  # 添加最后一页
    
    return pages
