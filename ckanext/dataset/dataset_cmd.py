from ckan.lib.cli import CkanCommand
import sys
import logging
from pprint import pprint

log = logging.getLogger('ckanext')
log.setLevel(logging.DEBUG)
import db

class DatasetCmd(CkanCommand):
    """Init required vocabs
        Usage:
        dataset-cmd vocab-delete
        - deletes created vocabulary
    """
    
    summary = __doc__.split('\n')[0]
    usage = __doc__
    #max_args = 3
    #min_args = 0
    
    def __init__(self, name):
        super(DatasetCmd, self).__init__(name)
    def command(self):
        self._load_config()
              
        if len(self.args) == 0:
            self.parser.print_usage()
            sys.exit(1)
        cmd = self.args[0]
        if cmd == 'initdb':
            log.info('Starting db initialization')
            if not db.tag_info_table.exists():
                log.info("creating tag_info table")
                db.tag_info_table.create()
                log.info("tag_info table created successfully")
            else:
                log.info("tag_info table already exists")

        if cmd == 'vocab-delete-per':
            import ckan.plugins.toolkit as toolkit
            log.info('Deleting vocabulary periodicities')
            try:
                vocab = toolkit.get_action('vocabulary_show')(data_dict={'id': 'periodicities'})
                tags = vocab['tags']
                log.info('tags: %s', tags)
                for tag in tags:
                    res = toolkit.get_action('tag_delete')(data_dict={'id': tag['id']})
            #        #log.info(res)
            #    log.info(vocab)
                res = toolkit.get_action('vocabulary_delete')(data_dict={'id' : vocab['id']})
            #    #log.info(res)
                log.info('vocabulary deleted')
            except toolkit.ObjectNotFound:
                log.warn('Vocabulary "periodicities" does not exist!')
        if cmd == 'vocab-delete-geo':
            import ckan.plugins.toolkit as toolkit
            log.info('Deleting vocabulary geo_tags')
            try:
                vocab = toolkit.get_action('vocabulary_show')(data_dict={'id': 'geo_tags'})
                tags = vocab['tags']
                log.info('tags: %s', tags)
                for tag in tags:
                    toolkit.get_action('ckanext_dataset_delete_tag_info')(data_dict={'tag_id': tag['id']})
                    toolkit.get_action('tag_delete')(data_dict={'id': tag['id']})
                res = toolkit.get_action('vocabulary_delete')(data_dict={'id' : vocab['id']})
                log.info('vocabulary deleted')
            except toolkit.ObjectNotFound:
                log.warn('Vocabulary "geo_tags" does not exist!')

        if cmd == 'vocab-per-add-tag':
            import ckan.plugins.toolkit as toolkit
            log.info('adding tag to vocabulary periodicity')
            tag_name = self.args[1]
            vocab = toolkit.get_action('vocabulary_show')(data_dict={'id': 'periodicities'})
            new_tag = toolkit.get_action('tag_create')(data_dict={'name' : tag_name,'vocabulary_id': vocab['id']})
            log.info('tag created with ID: %s', new_tag['id'])

        if cmd == 'vocab-geo-add-tag':
            import ckan.plugins.toolkit as toolkit
            log.info('adding tag to vocabulary geo_tags')
            tag_name = self.args[1]
            tag_geojson = self.args[2]
            vocab = toolkit.get_action('vocabulary_show')(data_dict={'id': 'geo_tags'})
            new_tag = toolkit.get_action('tag_create')(data_dict={'name' : tag_name,'vocabulary_id': vocab['id']})
            data = {'key' : 'spatial', 'value' : tag_geojson, 'tag_id' : new_tag['id']}
            toolkit.get_action('ckanext_dataset_create_tag_info')(data_dict=data)
            log.info('tag created with ID: %s', new_tag['id'])

        if cmd == 'force-data-migration':
            import ckan.plugins.toolkit as toolkit
            import ckan.model as model
            log.info('process of data migration has started')
            user = toolkit.get_action('get_site_user')({'ignore_auth': True}, {})
            context = {'model': model, 'session': model.Session, 'ignore_auth': True, 'user': user['name']}
            vocab_periodicity_tags = toolkit.get_action('vocabulary_show')(data_dict={'id': 'periodicities'})['tags']
            periodicity_values = [tag['name'] for tag in vocab_periodicity_tags]
            organization_list = toolkit.get_action('organization_list')(context, {})
            # access model directly to get around validators etc...
            for org in organization_list:
                org_detail = toolkit.get_action('organization_show')(context, {'id' : org})
                for package in org_detail['packages']:
                    log.info('migrating dataset: %s', package['name'])
                    dataset = model.Package.get(unicode(package['name']))
                    for resource in dataset.resources:
                        per_value = resource.extras.get('periodicity')
                        status = resource.extras.get('status')
                        arg = self.args[1]
                        if arg == 'set':
                            resource.extras['periodicity'] = 'daily'
                        if not status in ['private', 'public']:
                            resource.extras['status'] = 'private'
                        if not per_value in periodicity_values and not per_value=='':
                            #set undefined
                            if status == 'private':
                                resource.extras['periodicity'] = ''
                            else:
                                #set annually is default valid option for public resources
                                resource.extras['periodicity'] = 'annually'
                    rev = model.repo.new_revision()
                    dataset.save()
            log.info('process of data migration successfully finished')
