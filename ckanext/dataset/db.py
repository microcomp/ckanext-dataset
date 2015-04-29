import datetime
import uuid

from ckan.model import domain_object
from ckan.model.meta import metadata, Session, mapper
from sqlalchemy import types, Column, Table, ForeignKey, func, CheckConstraint

def make_uuid():
    return unicode(uuid.uuid4())

class TagInfo(domain_object.DomainObject):

        @classmethod
        def get(cls, **kw):
            '''Finds a single entity in the register.'''
            query = Session.query(cls).autoflush(False)
            return query.filter_by(**kw).all()

        @classmethod
        def tag_info(cls, **kw):
            '''Finds a single entity in the register.'''
            order = kw.pop('order', False)

            query = Session.query(cls).autoflush(False)
            query = query.filter_by(**kw)
            if order:
                query = query.order_by(cls.order).filter(cls.order != '')
            return query.all()
        
        @classmethod
        def delete(cls, **kw):
            query = Session.query(cls).autoflush(False).filter_by(**kw).all()
            for i in query:
                Session.delete(i)
            return

tag_info_table = Table('ckanext_tag_info', metadata,
        Column('id', types.UnicodeText, primary_key=True, default=make_uuid),
        Column('tag_id', types.UnicodeText, default=u''),
        Column('key', types.UnicodeText, default=u''),
        Column('value', types.UnicodeText, default=u'')
    )

mapper(TagInfo, tag_info_table)
