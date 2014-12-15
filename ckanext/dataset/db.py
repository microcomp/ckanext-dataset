import datetime
import uuid

import sqlalchemy as sa
from sqlalchemy.orm import class_mapper


tag_info_table = None
TagInfo = None


def make_uuid():
    return unicode(uuid.uuid4())


def init_db(model):
    class _TagInfo(model.DomainObject):

        @classmethod
        def get(cls, **kw):
            '''Finds a single entity in the register.'''
            query = model.Session.query(cls).autoflush(False)
            return query.filter_by(**kw).all()

        @classmethod
        def tag_info(cls, **kw):
            '''Finds a single entity in the register.'''
            order = kw.pop('order', False)

            query = model.Session.query(cls).autoflush(False)
            query = query.filter_by(**kw)
            if order:
                query = query.order_by(cls.order).filter(cls.order != '')
            return query.all()

    global TagInfo
    TagInfo = _TagInfo
    # We will just try to create the table.  If it already exists we get an
    # error but we can just skip it and carry on.
    sql = '''
                CREATE TABLE ckanext_tag_info (
                    id text NOT NULL,
                    tag_id text NOT NULL,
                    key text,
                    value text
                );
    '''
    conn = model.Session.connection()
    try:
        conn.execute(sql)
    except sa.exc.ProgrammingError:
        model.Session.rollback()
    model.Session.commit()

    types = sa.types
    global tag_info_table
    tag_info_table = sa.Table('ckanext_tag_info', model.meta.metadata,
        sa.Column('id', types.UnicodeText, primary_key=True, default=make_uuid),
        sa.Column('tag_id', types.UnicodeText, default=u''),
        sa.Column('key', types.UnicodeText, default=u''),
        sa.Column('value', types.UnicodeText, default=u'')
    )

    model.meta.mapper(
        TagInfo,
        tag_info_table,
    )


def table_dictize(obj, context, **kw):
    '''Get any model object and represent it as a dict'''
    result_dict = {}

    if isinstance(obj, sa.engine.base.RowProxy):
        fields = obj.keys()
    else:
        ModelClass = obj.__class__
        table = class_mapper(ModelClass).mapped_table
        fields = [field.name for field in table.c]

    for field in fields:
        name = field
        if name in ('current', 'expired_timestamp', 'expired_id'):
            continue
        if name == 'continuity_id':
            continue
        value = getattr(obj, name)
        if value is None:
            result_dict[name] = value
        elif isinstance(value, dict):
            result_dict[name] = value
        elif isinstance(value, int):
            result_dict[name] = value
        elif isinstance(value, datetime.datetime):
            result_dict[name] = value.isoformat()
        elif isinstance(value, list):
            result_dict[name] = value
        else:
            result_dict[name] = unicode(value)

    result_dict.update(kw)

    ##HACK For optimisation to get metadata_modified created faster.

    context['metadata_modified'] = max(result_dict.get('revision_timestamp', ''),
                                       context.get('metadata_modified', ''))

    return result_dict

