# -*- coding: utf-8 -*-
import ckan.lib.navl.dictization_functions as df

import ckan.model as model
import logging
import datetime
import re
import ckan.plugins as plugins
import ckan.plugins.toolkit as tk
import ckan.lib.navl.dictization_functions as df
import ckan.lib.helpers as h
import json
import os
import db
import dataset_logic
import ckan.logic


_ = tk._
missing = df.missing
StopOnError = df.StopOnError
data_path = "/data/"
validity_possible_values = ['perm_valid', 'custom_valid', 'other']
correctness_possible_values = ['correct and exact', 'incorrect or inexact', 'stated in data']


log = logging.getLogger(__name__)

def custom_ignore_missing(key, data, errors, context):
    '''If the key is missing from the data, ignore the rest of the key's
    schema.

    By putting ignore_missing at the start of the schema list for a key,
    you can allow users to post a dict without the key and the dict will pass
    validation. But if they post a dict that does contain the key, then any
    validators after ignore_missing in the key's schema list will be applied.

    :raises ckan.lib.navl.dictization_functions.StopOnError: if ``data[key]``
        is :py:data:`ckan.lib.navl.dictization_functions.missing` or ``None``

    :returns: ``None``

    '''
    value = data.get(key)
    if value is missing or value is None:
        if _retrieve_key_value('status', key, data) != 'public':
            #errors[key].append(_('Missing attribute {0}').format(key))
            data.pop(key, None)
            raise StopOnError


def _is_missing(key, data):
    value = data.get(key)
    if value is missing or value is None:
        return True
    return False

def resource_validator(key, data, errors, context):
    origin_key_list = list(key)
    origin_key_list[2]='status'
    status_key = tuple(origin_key_list)
    status_value = data.get(status_key,'')
    log.info('resource validator')
    log.info('key: %s', key)
    log.info('status key: %s', status_key)
    log.info('status value: %s', status_value)
    log.info('status value type: %s', type(status_value))
    if _is_missing(status_key, data) or not status_value in ['private', 'public']:
        data[status_key] = unicode('private')
        

def owner_org_validator(key, data, errors, context):
    roles = tk.get_action('enum_roles')(data_dict={})
    if roles.MOD_R_DATA in tk.get_action('user_custom_roles')(context):
        model = context['model']
        value = data.get(key)
        group = model.Group.get(value)
        if not group:
            raise df.Invalid(_('Organization does not exist'))
        group_id = group.id
        data[key] = group_id
    else:
        tk.get_validator('owner_org_validator')(key, data, errors, context)
        
def _retrieve_key_value(key_name, key, data):
    origin_key_list = list(key)
    origin_key_list[2]= key_name
    custom_key = tuple(origin_key_list)
    return data.get(custom_key, None)

def _clear_key_value(key_name, key, data):
    origin_key_list = list(key)
    origin_key_list[2]= key_name
    custom_key = tuple(origin_key_list)
    if custom_key in data:
        data[custom_key] = ''

def valid_periodicity_text(key, data, errors, context):
    value = data[key]
    periodicity_value = _retrieve_key_value('periodicity', key, data)
    if _retrieve_key_value('status', key, data) =='public' and periodicity_value == 'iné':
        min_length = 10
        if len(value)<min_length:
            errors[key].append(_('Please insert a description. The mimimal length is {0} characters').format(min_length))
  
def valid_corretness(key, data, errors, context):
    global correctness_possible_values
    value = data[key]
    if data[key] == correctness_possible_values[0] or data[key] == correctness_possible_values[1]:
        _clear_key_value('data_correctness_description', key, data)
    if _retrieve_key_value('status', key, data) =='public':
        if not value in validity_possible_values:
            errors[key].append(_('Please select the type of validity!'))
        

def valid_text(key, data, errors, context):
    global validity_possible_values
    value = data[key]
    validity_value = _retrieve_key_value('validity', key, data)
    if _retrieve_key_value('status', key, data) =='public' and _retrieve_key_value('validity', key, data) == validity_possible_values[1]:
        min_length = 10
        if len(value)<min_length:
            errors[key].append(_('Please insert a description. The mimimal length is {0} characters').format(min_length))
 
def validator_validity(key, data, errors, context):
    global validity_possible_values
    value = data[key]
    missing = _is_missing(key, data)
    if _retrieve_key_value('status', key, data) =='public':
        if missing:
            errors[key].append(_('Missing attribute {0}!').format(key[2]))
        if not value in validity_possible_values:
            errors[key].append(_('Please select the type of validity!'))
    else:
        #no key
        if missing:
            data.pop(key, None)
            raise StopOnError
        else:
        #if key is present, it has to have reasonable value
            if not value in validity_possible_values and value!='':
                errors[key].append(_('Please select the type of validity!'))

def validator_date(key, data, errors, context):
    global validity_possible_values
    missing = _is_missing(key, data)
    value = data[key]
    validity_value = _retrieve_key_value('validity', key, data)
    status = _retrieve_key_value('status', key, data)
    if validity_value == validity_possible_values[2]:
        if missing:
            errors[key].append(_('Missing attribute {0}!').format(key[2]))
            data.pop(key, None)
            raise StopOnError
        else:
            if (value != '' and status =='private') or status =='public':
                try:
                    valid_date = tk.get_validator('isodate')(value, context)
                    if not valid_date or not isinstance(valid_date, datetime.datetime):
                            errors[key].append(_('Date format incorrect'))
                except (TypeError, ValueError), e:
                    errors[key].append(_('Date format incorrect'))
    else:
        if not missing:
            data[key] = ''
        if missing and status =='private':
            data.pop(key, None)
            raise StopOnError

def validator_validity_descr(key, data, errors, context):
    global validity_possible_values
    missing = _is_missing(key, data)
    value = data[key]
    validity_value = _retrieve_key_value('validity', key, data)
    status = _retrieve_key_value('status', key, data)
    if validity_value == validity_possible_values[1]:
        if missing:
            errors[key].append(_('Missing attribute {0}!').format(key[2]))
            data.pop(key, None)
            raise StopOnError
        else:
            if (value != '' and status =='private') or status =='public':
                #TODO REGEX
                if len(value)<1:
                    errors[key].append(_('Please provide an explanation of validity'))
    else:
        if not missing:
            data[key] = ''
        if missing and status =='private':
            data.pop(key, None)
            raise StopOnError
            
def validator_periodicity(key, data, errors, context):
    periodicity_possible_values = periodicities()
    value = data[key]
    if type(value) is list:
        value = value[0]
    status = _retrieve_key_value('status', key, data)
    missing = _is_missing(key, data)
    if not missing:
        if not value in periodicity_possible_values and value!='':
            errors[key].append(_('Please enter a valid value!'))
        else:
            if value=='' and status =='public':
                errors[key].append(_('Please select an option!'))
    else:
        if status=='public':
            errors[key].append(_('Missing attribute {0}!').format(key[2]))
        data.pop(key, None)
        raise StopOnError
    
def validator_periodicity_descr(key, data, errors, context):
    periodicity = _retrieve_key_value('periodicity', key, data)
    status = _retrieve_key_value('status', key, data)
    value = data[key]
    missing = _is_missing(key, data)
    if periodicity == 'other':
        if missing:
            errors[key].append(_('Missing attribute {0}!').format(key[2]))
            data.pop(key, None)
            raise StopOnError
        if value == '' and status == 'public':
            errors[key].append(_('Please enter a periodicity description!'))
    else:
        if not missing:
            data[key] = ''
        else:
            data.pop(key, None)
            raise StopOnError

def validator_data_correctness(key, data, errors, context):
    global correctness_possible_values
    status = _retrieve_key_value('status', key, data)
    value = data[key]
    missing = _is_missing(key, data)
    if not missing:
        #unexpected value
        if value != '' and not value in correctness_possible_values:
            errors[key].append(_('Please enter a valid option!'))
        #undefined or empty
        if value == '' and status=='public':
            errors[key].append(_('Please select appropriate option!'))
    else:
        if status=='public':
            errors[key].append(_('Missing attribute {0}!').format(key[2]))
        data.pop(key, None)
        raise StopOnError

def validator_data_correctness_descr(key, data, errors, context):
    global correctness_possible_values
    status = _retrieve_key_value('status', key, data)
    data_correctness = _retrieve_key_value('data_correctness', key, data)
    value = data[key]
    missing = _is_missing(key, data)
    if data_correctness == correctness_possible_values[2]:
        if missing:
            errors[key].append(_('Missing attribute {0}!').format(key[2]))
            data.pop(key, None)
            raise StopOnError
        if value=='' and status=='public':
            errors[key].append(_('Please fill in this field!'))
    else:
        if not missing:
            data[key] = ''
        else:
            data.pop(key, None)
            raise StopOnError

def validator_spatial(key, data, errors, context):
    value = data[key]
    private = data.get(('private',), False)
    missing = _is_missing(key, data)
    if not missing:
        if not private and (not value or value=='undefined'):
            errors[key].append(_('Please select an appropriate option!'))
    else:
        if not private:
            errors[key].append(_('Missing attribute!'))
        data.pop(key, None)
        raise StopOnError
        
        

def validator_url(value, context):
    if value=='':
        return value
    regex = re.compile(
    r'^(?:http|ftp)s?://' # http:// or https://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' # domain...
    r'localhost|' # localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|' # ...or ipv4
    r'\[?[A-F0-9]*:[A-F0-9:]+\]?)' # ...or ipv6
    r'(?::\d+)?' # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    if regex.match(value):
        return value
    raise df.Invalid(_('Please provide a valid URL'))

def validator_selected_option(value, context):
    if value == 'Undefined':
        raise df.Invalid(_('Please select a location'))
    return value

def validator_status(value, context):
    if value == 'private' or value == 'public':
        return value
    raise df.Invalid(_('The possible values for status are "private" or "public"'))

def create_tag_info_table(context):
    if not db.tag_info_table.exists():
        db.tag_info_table.create()

@ckan.logic.side_effect_free
def insert_tag_info(context, data_dict):
    '''
    This function inserts an extra value for given tag_id in the form key:value.
    data_dict must have keys tag_id, key, value.
    '''
    create_tag_info_table(context)
    info = db.TagInfo()
    info.tag_id = data_dict.get('tag_id')
    info.key = data_dict.get('key')
    info.value = data_dict.get('value')
    info.save()
    return {"status":"success"}

@ckan.logic.side_effect_free
def get_tag_info(context, data_dict):
    '''
    This function retrieves extra information about given tag_id and
    possibly more filtering criterias. 
    '''
    res = db.TagInfo.get(**data_dict)
    return res

@ckan.logic.side_effect_free
def delete_tag_info(context, data_dict):
    tag_id = data_dict['tag_id']
    db.tag_info_table.delete(db.TagInfo.tag_id==tag_id).execute()
    
def extract_data():
    def _extract_data_from_file(abs_path):
        json_data=open(abs_path)
        entries = []
        data = json.load(json_data)
        for entry in data['features']:
            s = (entry['properties']['TXT'], entry['properties']['REF'], json.dumps(entry['geometry']))
            log.info(s)
            entries.append(s)
        json_data.close()
        return entries
    
    script_dir = os.path.dirname(__file__)
    abs_path = script_dir + data_path
    f = []
    for (dirpath, dirnames, filenames) in os.walk(abs_path):
        f.extend(filenames)
        break
    res=[]
    for file_name in f:
        res.extend(_extract_data_from_file(abs_path+file_name))

    return res

def create_geo_tags():

    user = tk.get_action('get_site_user')({'ignore_auth': True}, {})
    context = {'user': user['name']}
    try:
        data = {'id': 'geo_tags'}
        tk.get_action('vocabulary_show')(context, data)
        log.info("geo_tags vocabulary already exists, skipping.")
    except tk.ObjectNotFound:
        logging.info("Creating vocab 'geo_tags'")
        data = {'name': 'geo_tags'}
        vocab = tk.get_action('vocabulary_create')(context, data)
        for tag in extract_data():
            data = {'name': tag[0], 'vocabulary_id': vocab['id']}
            try:
                new_tag = tk.get_action('tag_create')(context, data)
                tag_id = new_tag.get('id')
                data = {'key' : 'spatial', 'value' : tag[2], 'tag_id' : tag_id}
                tk.get_action('ckanext_dataset_create_tag_info')(data_dict=data)
                data = {'key' : 'ref', 'value' : tag[1], 'tag_id' : tag_id}
                tk.get_action('ckanext_dataset_create_tag_info')(data_dict=data)
            except tk.ValidationError:
                log.info('tag already in vocab')
            
    
def geo_tags():
    '''Return the list of country codes from the country codes vocabulary.'''
    create_geo_tags()
    try:
        geo_tags = tk.get_action('tag_list')(
        data_dict={'vocabulary_id': 'geo_tags'})
        return geo_tags
    except tk.ObjectNotFound:
        return None


def create_periodicities():
    '''Create country_codes vocab and tags, if they don't exist already.
    Note that you could also create the vocab and tags using CKAN's API,
    and once they are created you can edit them (e.g. to add and remove
    possible dataset country code values) using the API.
    '''
    just_for_translation = (_('annually'), _('semi-annually'), _('quarterly'), _('monthly'), _('weekly'), _('daily'), _('irregularly'), _('other'))
    p = ( u'annually', u'semi-annually', u'quarterly', u'monthly', u'weekly', u'daily', u'irregularly', u'other')
    user = tk.get_action('get_site_user')({'ignore_auth': True}, {})
    context = {'user': user['name']}
    try:
        data = {'id': 'periodicities'}
        res = tk.get_action('vocabulary_show')(context, data)
        v = res.get('tags')
        tag_names = [tag.get('display_name') for tag in v]
        log.info('---tag names---')
        log.info(tag_names)
        if len(tag_names)!=len(p):
            for name in p:
                if name not in tag_names:
                    log.info("Adding tag {0} to vocab 'periodicities'".format(name))
                    data = {'name': name, 'vocabulary_id': res['id']}
                    tk.get_action('tag_create')(context, data)
        else:
            log.info("Periodicities vocabulary already exists, skipping.")
    except tk.ObjectNotFound:
        log.info("Creating vocab 'periodicities'")
        data = {'name': 'periodicities'}
        vocab = tk.get_action('vocabulary_create')(context, data)
        for tag in p:
            log.info("Adding tag {0} to vocab 'periodicities'".format(tag))
            data = {'name': tag, 'vocabulary_id': vocab['id']}
            tk.get_action('tag_create')(context, data)

def periodicities():
    '''Return the list of country codes from the country codes vocabulary.'''
    create_periodicities()
    try:
        #res=tk.get_action('tag_autocomplete')(data_dict={'query' : 'y', 'vocabulary_id' : 'periodicities'})
        #log.info(res)
        periodicity = tk.get_action('tag_list')(
        data_dict={'vocabulary_id': 'periodicities'})
        log.info(periodicity)
        periodicity_translated = [name for name in periodicity] 
        return periodicity_translated
    except tk.ObjectNotFound:
        return None

def retrieve_name_of_geojson(json_value):
    log.info('retrieve name to geojson: %s', json_value)
    if json_value:
        res = tk.get_action('ckanext_dataset_get_tag_info')(data_dict={'value': json_value})
        if res:
            for tag_info in res:
                tag = tk.get_action('tag_show')(data_dict={'id' : tag_info.tag_id})
                if tag:
                    return tag.get('name', None)
                raise Exception('Inconsistency in database between table tags and ckanext_tag_info ')
    return None

def retrieve_geojson(data_extras):
    if not data_extras:
        return ''
    for extra in data_extras:
        if extra.get('key', '') == 'spatial':
            return extra.get('value', '')
    return ''
        
 
def get_users(data):
    users = tk.get_action('user_list')(data_dict={})
    return users, tk.c.user
def get_name(login):
    user_obj = model.Session.query(model.User).filter(model.User.name == login).first()
    if user_obj:
        return user_obj.fullname
    return login



class ExtendedDatasetPlugin(plugins.SingletonPlugin, tk.DefaultDatasetForm):
    plugins.implements(plugins.IConfigurer, inherit=False)
    plugins.implements(plugins.IDatasetForm, inherit=False)
    plugins.implements(plugins.ITemplateHelpers, inherit=False)
    plugins.implements(plugins.IActions, inherit=False)
    plugins.implements(plugins.IResourceController, inherit=True)
    
    num_times_new_template_called = 0
    num_times_read_template_called = 0
    num_times_edit_template_called = 0
    num_times_search_template_called = 0
    num_times_history_template_called = 0
    num_times_package_form_called = 0
    num_times_check_data_dict_called = 0
    num_times_setup_template_variables_called = 0

    def before_show(self, resource_dict):
        log.info("resource before show: %s", resource_dict)
        try:
            ckan.logic.check_access('resource_show', {},resource_dict)
            return resource_dict
        except tk.NotAuthorized, e:
            resource_dict.clear()
            return resource_dict

    def get_actions(self):
        return {'ckanext_dataset_create_tag_info' : insert_tag_info,
                'ckanext_dataset_get_tag_info' : get_tag_info,
                'ckanext_dataset_delete_tag_info' : delete_tag_info,
                'package_show' : dataset_logic.package_show,
                'resource_search' : dataset_logic.resource_search,
                'current_package_list_with_resources' : dataset_logic.current_package_list_with_resources,
                'is_resource_public' : dataset_logic.is_resource_dict_public,
                'datastore_query_changes' : dataset_logic.query_changes}
    
    def update_config(self, config):
        # Add this plugin's templates dir to CKAN's extra_template_paths, so
        # that CKAN will use this plugin's custom templates.
        tk.add_template_directory(config, 'templates')
        tk.add_public_directory(config, 'public')
        
    
    def get_helpers(self):
        return {'periodicities': periodicities,
                'geo_tags': geo_tags,
                'convert_geojson_to_name' : retrieve_name_of_geojson,
                'retrieve_geojson' : retrieve_geojson,
                'get_users' : get_users,
                'get_name' : get_name }
    
    def is_fallback(self):
        # Return True to register this plugin as the default handler for
        # package types not handled by any other IDatasetForm plugin.
        return True

    def package_types(self):
        # This plugin doesn't handle any special package types, it just
        # registers itself as the default (above).
        return []

    def _modify_package_schema(self, schema):
        # Add our custom_test metadata field to the schema, this one will use
        # convert_to_extras instead of convert_to_tags.

        schema.update({
                #'spatial': [tk.get_validator('ignore_missing'), validator_selected_option, tk.get_converter('convert_to_extras')],
                'spatial': [validator_spatial, tk.get_converter('convert_to_extras')],
                'owner_org': [tk.get_validator('ignore_missing'), owner_org_validator]
                })
        
        schema['resources'].update({
                        '__before' : [resource_validator],
                        'validity' : [validator_validity, unicode],
                        'valid_from' : [validator_date, unicode],
                        'valid_to' : [validator_date, unicode],
                        'active_from' : [validator_date, unicode],
                        'active_to' : [validator_date, unicode],
                        'validity_description' : [validator_validity_descr, unicode],
                        'periodicity' : [validator_periodicity, unicode],
                        'periodicity_description' : [validator_periodicity_descr, unicode],
                        'schema': [tk.get_validator('ignore_missing'), validator_url],
                        'data_correctness' : [validator_data_correctness, unicode],
                        'data_correctness_description' : [validator_data_correctness_descr, unicode],
                        'status' : [tk.get_validator('ignore_missing'), validator_status]
            })
        
        return schema

    def create_package_schema(self):
        schema = super(ExtendedDatasetPlugin, self).create_package_schema()
        schema = self._modify_package_schema(schema)
        return schema

    def update_package_schema(self):
        schema = super(ExtendedDatasetPlugin, self).update_package_schema()
        schema = self._modify_package_schema(schema)
        return schema

    def show_package_schema(self):
        schema = super(ExtendedDatasetPlugin, self).show_package_schema()
        schema.update({
            'spatial': [tk.get_converter('convert_from_extras'), validator_spatial]
                })
                
        schema['tags']['__extras'].append(tk.get_converter('free_tags_only'))
        schema['resources'].update({
                        '__before' : [resource_validator],
                        'validity' : [validator_validity, unicode],
                        'valid_from' : [validator_date, unicode],
                        'valid_to' : [validator_date, unicode],
                        'active_from' : [validator_date, unicode],
                        'active_to' : [validator_date, unicode],
                        'validity_description' : [validator_validity_descr, unicode],
                        #'periodicity' : [tk.get_converter('convert_from_tags')('periodicities'),validator_periodicity],
                        'periodicity' : [validator_periodicity, unicode],
                        'periodicity_description' : [validator_periodicity_descr, unicode],
                        'schema': [tk.get_validator('ignore_missing'), validator_url],
                        'data_correctness' : [validator_data_correctness, unicode],
                        'data_correctness_description' : [validator_data_correctness_descr, unicode],
                        'status' : [tk.get_validator('ignore_missing'), validator_status]
            })
        
        return schema

    # These methods just record how many times they're called, for testing
    # purposes.
    # TODO: It might be better to test that custom templates returned by
    # these methods are actually used, not just that the methods get
    # called.

    def setup_template_variables(self, context, data_dict):
        ExtendedDatasetPlugin.num_times_setup_template_variables_called += 1
        return super(ExtendedDatasetPlugin, self).setup_template_variables(
                context, data_dict)

    def new_template(self):
        ExtendedDatasetPlugin.num_times_new_template_called += 1
        return super(ExtendedDatasetPlugin, self).new_template()

    def read_template(self):
        ExtendedDatasetPlugin.num_times_read_template_called += 1
        return super(ExtendedDatasetPlugin, self).read_template()

    def edit_template(self):
        ExtendedDatasetPlugin.num_times_edit_template_called += 1
        return super(ExtendedDatasetPlugin, self).edit_template()

    def search_template(self):
        ExtendedDatasetPlugin.num_times_search_template_called += 1
        return super(ExtendedDatasetPlugin, self).search_template()

    def history_template(self):
        ExtendedDatasetPlugin.num_times_history_template_called += 1
        return super(ExtendedDatasetPlugin, self).history_template()

    def package_form(self):
        ExtendedDatasetPlugin.num_times_package_form_called += 1
        return super(ExtendedDatasetPlugin, self).package_form()

    # check_data_dict() is deprecated, this method is only here to test that
    # legacy support for the deprecated method works.
    def check_data_dict(self, data_dict, schema=None):
        ExtendedDatasetPlugin.num_times_check_data_dict_called += 1