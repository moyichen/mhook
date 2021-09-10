# !/usr/bin/python3
# -*- coding: utf8 -*-
# author: moyichen
# date:   2019-08-20
import re

from utils import *
import pyecharts.options as opts
from pyecharts.charts import Line, Page, Bar, Pie, Grid

"""
    https://gallery.pyecharts.org/#/README
"""


def plot_div(figure_or_data):
    page = Page()
    page.add(figure_or_data)
    div = page.render_embed()

    pattern = '(<div id=.*></div>.*?<br/>)'
    m = re.search(pattern, div, re.DOTALL)
    if m:
        div = m.group(1)

    return div


def plot_bar(data, title=None, subtitle=None, xaxis=None, yaxis=None):
    """条形图

        Args:
            bars (list): 每个元素代表一条线, 其中键值x,y分别包含两个相同长度的坐标轴,
                {
                    "x": [1,2,3],
                    "y": [1,2,3],
                    "name": [SCATTER_NAME],
                    “kwargs”: {}
                }

            title (str, optional): 标题. Defaults to None.
            xaxis (str, optional): x坐标名称. Defaults to None.
            yaxis (str, optional): y坐标名称. Defaults to None.
        """

    init_opts = opts.InitOpts()
    markline_opts = opts.MarkLineOpts(data=[opts.MarkLineItem(type_="average", name="average")])
    markpoint_opts = opts.MarkPointOpts(
        data=[
            opts.MarkPointItem(type_="max", name="max"),
            opts.MarkPointItem(type_="min", name="min"),
        ])

    b = Bar(init_opts=init_opts)

    b.add_xaxis(data['x'])

    b.add_yaxis(series_name=yaxis, yaxis_data=data['y'], markline_opts=markline_opts, markpoint_opts=markpoint_opts)

    b.set_series_opts(label_opts=opts.LabelOpts(is_show=False))
    b.set_global_opts(
            title_opts=opts.TitleOpts(title=title, subtitle=subtitle),
            datazoom_opts=opts.DataZoomOpts(type_="inside"),
            xaxis_opts=opts.AxisOpts(
                axistick_opts=opts.AxisTickOpts(is_align_with_label=True),
                axislabel_opts=opts.LabelOpts(rotate=-15),
                is_scale=False,
            ),
            legend_opts=opts.LegendOpts(pos_bottom='1'))

    return plot_div(b)


def plot_pie(pie, title=None, xaxis=None, yaxis=None):
    x_len = len(pie['x'])
    y_len = len(pie['y'])
    if x_len != y_len or x_len == 0:
        return "No Data"
    c = Pie()
    c.add(xaxis, [list(z) for z in zip(pie['x'], pie['y'])], radius=["40%", "75%"])
    c.set_global_opts(title_opts=opts.TitleOpts(title=title))
    c.set_series_opts(label_opts=opts.LabelOpts(formatter="{b}: {c}, {d}%",)
                      )

    return plot_div(c)


def plot_grid(traces):
    grid = Grid()
    grid.add(traces[0], grid_opts=opts.GridOpts(pos_right="50%"))
    grid.add(traces[1], grid_opts=opts.GridOpts(pos_left="50%"))
    return grid


def plot_scatter(scatters, title=None, xaxis=None, yaxis=None):
    """点线图

    Args:
        scatters (list): 每个元素代表一条线, 其中键值x,y分别包含两个相同长度的坐标轴,
            {
                "x": [1,2,3],
                "y": [1,2,3],
                "name": [SCATTER_NAME],
                “kwargs”: {}
            }

        title (str, optional): 标题. Defaults to None.
        xaxis (str, optional): x坐标名称. Defaults to None.
        yaxis (str, optional): y坐标名称. Defaults to None.
        hoverinfo='text+name'
        mode='lines+markers'
        line=dict(color=colors[i], width=line_size[i])
        marker=dict(color=colors[i], size=mode_size[i])
        connectgaps=True,
        line_shape='spline','linear','vhv','hvh','vh','hv'
    """
    div = ''

    mark_point_opts = opts.MarkPointOpts(
        data=[
            opts.MarkPointItem(type_="max", name="最大值"),
            opts.MarkPointItem(type_="min", name="最小值"),
        ]
    )
    mark_line_opts = opts.MarkLineOpts(
        data=[opts.MarkLineItem(type_="average", name="平均值")]
    )

    for idx, scatter in enumerate(scatters):
        ln = Line(opts.InitOpts())

        ln.add_xaxis(xaxis_data=range(0, len(scatter['x'])))
        ln.add_yaxis(series_name=yaxis, y_axis=scatter['y'], markline_opts=mark_line_opts, markpoint_opts=mark_point_opts)
        ln.set_series_opts(label_opts=opts.LabelOpts(is_show=False))
        ln.set_global_opts(
                title_opts=opts.TitleOpts(title=title),
                tooltip_opts=opts.TooltipOpts(trigger="axis"),
                toolbox_opts=opts.ToolboxOpts(is_show=True),
                datazoom_opts=opts.DataZoomOpts(type_="inside"),
                xaxis_opts=opts.AxisOpts(
                    type_="category",
                    axistick_opts=opts.AxisTickOpts(is_align_with_label=True),
                    is_scale=False,
                    boundary_gap=False,
                ),
                yaxis_opts=opts.AxisOpts(splitline_opts=opts.SplitLineOpts(is_show=True)),
                legend_opts=opts.LegendOpts(pos_bottom='1'))
        div += plot_div(ln)
    return div


def plot_report(figure, filename='report.html'):
    html_header = """
    <!DOCTYPE html>
    <html>
        <head>
            <meta charset="UTF-8">
            <script type="text/javascript" src="https://assets.pyecharts.org/assets/echarts.min.js"></script>
        </head>
    <body>
        <style>.box {  }; </style>
        <div class="box">
    """
    html_suffix = """
        </div>
    </body>
    </html>
    """
    safe_make_dirs(os.path.dirname(filename))
    with open(filename, 'w+') as f:
        f.write("\n".join([html_header] + figure + [html_suffix]))


if __name__ == '__main__':
    c = plot_pie({'x':['a', 'b', 'c'], 'y':[10, 40, 50]})
    c1 = plot_pie({'x': ['a0', 'b0', 'c0'], 'y': [10, 40, 50]})
    c2 = plot_bar({'x': ['a0', 'b0', 'c0'], 'y': [10, 40, 50]})
    c3 = plot_scatter({'x': [1, 2, 3], 'y': [10, 40, 50]})
    plot_report([c, c1, c2, c3])
