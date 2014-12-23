import logging

import ckan.plugins as plugins
import ckan.plugins.toolkit as tk

import json
import os

import db
import ckan.logic

data_path = "/data/"


log = logging.getLogger(__name__)

def create_tag_info_table(context):
    if db.tag_info_table is None:
        db.init_db(context['model'])

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
    session = context['session']
    session.add(info)
    session.commit()
    return {"status":"success"}

@ckan.logic.side_effect_free
def get_tag_info(context, data_dict):
    '''
    This function retrieves extra information about given tag_id and
    possibly more filtering criterias. 
    '''
    if db.tag_info_table is None:
        db.init_db(context['model'])
    res = db.TagInfo.get(**data_dict)
    return res

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
    '''Create country_codes vocab and tags, if they don't exist already.
    Note that you could also create the vocab and tags using CKAN's API,
    and once they are created you can edit them (e.g. to add and remove
    possible dataset country code values) using the API.
    '''
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
            #logging.info("Adding tag {0} to vocab 'periodicities'".format(tag[0]))
            data = {'name': tag[0], 'vocabulary_id': vocab['id']}
            new_tag = tk.get_action('tag_create')(context, data)
            tag_id = new_tag.get('id')
            data = {'key' : 'spatial', 'value' : tag[2], 'tag_id' : tag_id}
            tk.get_action('ckanext_dataset_create_tag_info')(data_dict=data)
            data = {'key' : 'ref', 'value' : tag[1], 'tag_id' : tag_id}
            tk.get_action('ckanext_dataset_create_tag_info')(data_dict=data)
            
    
def geo_tags():
    '''Return the list of country codes from the country codes vocabulary.'''
    create_geo_tags()
    try:
        geo_tags = tk.get_action('tag_list')(
        data_dict={'vocabulary_id': 'geo_tags'})
        log.info(geo_tags)
        return geo_tags
    except tk.ObjectNotFound:
        return None


def create_periodicities():
    '''Create country_codes vocab and tags, if they don't exist already.
    Note that you could also create the vocab and tags using CKAN's API,
    and once they are created you can edit them (e.g. to add and remove
    possible dataset country code values) using the API.
    '''
    user = tk.get_action('get_site_user')({'ignore_auth': True}, {})
    context = {'user': user['name']}
    try:
        data = {'id': 'periodicities'}
        tk.get_action('vocabulary_show')(context, data)
        log.info("Periodicities vocabulary already exists, skipping.")
    except tk.ObjectNotFound:
        log.info("Creating vocab 'periodicities'")
        data = {'name': 'periodicities'}
        vocab = tk.get_action('vocabulary_create')(context, data)
        for tag in (u'yearly', u'monthly', u'weekly', u'daily'):
            log.info("Adding tag {0} to vocab 'periodicities'".format(tag))
            data = {'name': tag, 'vocabulary_id': vocab['id']}
            tk.get_action('tag_create')(context, data)

def periodicities():
    '''Return the list of country codes from the country codes vocabulary.'''
    create_periodicities()
    try:
        #log.info('autocomplete moj custom')
        #res=tk.get_action('tag_autocomplete')(data_dict={'query' : 'y', 'vocabulary_id' : 'periodicities'})
        #log.info(res)
        periodicity = tk.get_action('tag_list')(
        data_dict={'vocabulary_id': 'periodicities'})
        log.info(periodicity)
        return periodicity
    except tk.ObjectNotFound:
        return None

def retrieve_name_of_geojson(data_extras):
    if not data_extras:
        return None
    for extra in data_extras:
        if extra.get('key', None) == 'spatial':
            json_value = extra.get('value', None)
            res = tk.get_action('ckanext_dataset_get_tag_info')(data_dict={'value': json_value})
            if res:
                for tag_info in res:
                    tag = tk.get_action('tag_show')(data_dict={'id' : tag_info.tag_id})
                    if tag:
                        return tag.get('name', None)
                    raise Exception('Inconsistency in database between table tags and ckanext_tag_info ')
            return None    
    
def get_users(data):
    users = tk.get_action('user_list')(data_dict={})
    log.info(users)
    log.info('---current_user---')
    log.info(data)
    log.info(tk.c.user)
    return users, tk.c.user


class ExtendedDatasetPlugin(plugins.SingletonPlugin, tk.DefaultDatasetForm):
    plugins.implements(plugins.IConfigurer, inherit=False)
    plugins.implements(plugins.IDatasetForm, inherit=False)
    plugins.implements(plugins.ITemplateHelpers, inherit=False)
    plugins.implements(plugins.IActions, inherit=False)
    #plugins.implements(plugins.IPackageController, inherit=True)
    
    num_times_new_template_called = 0
    num_times_read_template_called = 0
    num_times_edit_template_called = 0
    num_times_search_template_called = 0
    num_times_history_template_called = 0
    num_times_package_form_called = 0
    num_times_check_data_dict_called = 0
    num_times_setup_template_variables_called = 0  
    
    def get_actions(self):
        return {'ckanext_dataset_create_tag_info' : insert_tag_info,
                'ckanext_dataset_get_tag_info' : get_tag_info}
    
    def update_config(self, config):
        # Add this plugin's templates dir to CKAN's extra_template_paths, so
        # that CKAN will use this plugin's custom templates.
        tk.add_template_directory(config, 'templates')
    
    def get_helpers(self):
        return {'periodicities': periodicities,
                'geo_tags': geo_tags,
                'convert_geojson_to_name' : retrieve_name_of_geojson,
                'get_users' : get_users }
    
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
        #tk.get_validator('ignore_missing'),
        #'schema_url' : [tk.get_validator('ignore_missing'), tk.get_converter('convert_to_extras')]
        schema.update({
                'spatial': [tk.get_validator('ignore_missing'), tk.get_converter('convert_to_extras')]
                })
               
        schema['resources'].update({
                        'valid_from' : [tk.get_validator('ignore_missing')],
                        'valid_to' : [tk.get_validator('ignore_missing')],
                        'schema': [tk.get_validator('ignore_missing')],
                        'periodicity' : [tk.get_validator('ignore_missing'), tk.get_converter('convert_to_tags')('periodicities')]
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

        # Don't show vocab tags mixed in with normal 'free' tags
        # (e.g. on dataset pages, or on the search page)
        
        # Add our custom_text field to the dataset schema.
        #'schema_url' : [tk.get_validator('ignore_missing'), tk.get_converter('convert_from_extras')]
        schema.update({
            'spatial': [tk.get_validator('ignore_missing'), tk.get_converter('convert_from_extras')]
                })
                
        schema['tags']['__extras'].append(tk.get_converter('free_tags_only'))
        schema['resources'].update({
                        'valid_from' : [tk.get_validator('ignore_missing')],
                        'valid_to' : [tk.get_validator('ignore_missing')],
                        'schema': [tk.get_validator('ignore_missing')],
                        'periodicity' : [tk.get_validator('ignore_missing'), tk.get_converter('convert_from_tags')('periodicities')]
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