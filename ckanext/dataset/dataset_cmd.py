from ckan.lib.cli import CkanCommand
import sys
import logging
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

        if cmd == 'vocab-delete':
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
            log.info('Deleting vocabulary geo_tags')
            try:
                vocab = toolkit.get_action('vocabulary_show')(data_dict={'id': 'geo_tags'})
                tags = vocab['tags']
                log.info('tags: %s', tags)
                for tag in tags:
                    toolkit.get_action('ckanext_dataset_delete_tag_info')(data_dict={'tag_id': tag['id']})
                    toolkit.get_action('tag_delete')(data_dict={'id': tag['id']})
            #        #log.info(res)
            #    log.info(vocab)
                res = toolkit.get_action('vocabulary_delete')(data_dict={'id' : vocab['id']})
            #    #log.info(res)
                log.info('vocabulary deleted')
            except toolkit.ObjectNotFound:
                log.warn('Vocabulary "geo_tags" does not exist!')

                