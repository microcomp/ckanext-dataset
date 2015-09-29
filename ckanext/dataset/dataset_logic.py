import socket
import json
import ckan
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import ckan.model as model
import ckan.new_authz as new_authz
import ckan.logic as logic
import ckan.logic.auth as logic_auth
import ckan.lib.navl.dictization_functions as df
import ckan.lib.dictization.model_dictize as model_dictize
import ckan.lib.search as search
import ckan.lib.plugins as lib_plugins
import sqlalchemy
import ckan.model.misc as misc
import logging
from pylons import session
import ckan.plugins.toolkit as toolkit
from _ast import alias
log = logging.getLogger(__name__)

_or_ = sqlalchemy.or_
_validate = df.validate
_table_dictize = ckan.lib.dictization.table_dictize
_check_access = logic.check_access
NotFound = logic.NotFound
ValidationError = logic.ValidationError
_get_or_bust = logic.get_or_bust
_ = toolkit._

def is_resource_dict_public(context, resource_dict):
    '''
    when a resource doesnt include a status attr, default is private status.
    only when status is set to true the resource is published
    '''
    status = resource_dict.get('status', '')
    if status=='public':
        return True
    else:
        return False

def audit_helper(context, input_data_dict, event):
    try:
        environ = toolkit.request.environ
    except TypeError:
        return  # no audit required for local actions
    #may be called via paster command
    environ = toolkit.request.environ
    path = environ.get('PATH_INFO', '')

    #check whether action was called via API
    if path.startswith('/api/'):
        audit_dict = {}
        api_key = environ.get('HTTP_AUTHORIZATION', '')
        if api_key:
            audit_dict['description'] = 'API KEY: ' + api_key
        user = context.get('user')
        if user:
            convert_user_name_or_id_to_id = toolkit.get_converter('convert_user_name_or_id_to_id')
            user_id = convert_user_name_or_id_to_id(user, context)
            audit_dict['subject'] = user_id
        else:
            audit_dict['subject'] = 'Anonymous user'
        actor_id = input_data_dict.get('actor_id', None)
        if not actor_id:
            actor_id = session.get('ckanext-cas-actorid', None)
        if actor_id:
            audit_dict['authorized_user'] = actor_id
        else:
            audit_dict['authorized_user'] = audit_dict['subject']
        audit_dict['event_name'] = event
        audit_dict['debug_level'] = 2
        audit_dict['error_code'] = 0
        if event.startswith('package'):
            audit_dict['object_reference'] = 'PackageID://' + context['package'].id
        else:
            audit_dict['object_reference'] = 'ResourceID://' + context['resource'].id
        toolkit.get_action('auditlog_send')(data_dict=audit_dict)

@ckan.logic.side_effect_free
def package_show(context, data_dict):
    '''Return the metadata of a dataset (package) and its resources.

    :param id: the id or name of the dataset
    :type id: string
    :param use_default_schema: use default package schema instead of
        a custom schema defined with an IDatasetForm plugin (default: False)
    :type use_default_schema: bool

    :rtype: dictionary

    '''
    model = context['model']
    context['session'] = model.Session
    name_or_id = data_dict.get("id") or _get_or_bust(data_dict, 'name_or_id')

    pkg = model.Package.get(name_or_id)
    if pkg is None:
        raise NotFound

    context['package'] = pkg

    toolkit.check_access('package_show', context, data_dict)

    if data_dict.get('use_default_schema', False):
        context['schema'] = logic.schema.default_show_package_schema()

    package_dict = None
    use_cache = (context.get('use_cache', True)
        and not 'revision_id' in context
        and not 'revision_date' in context)
    if use_cache:
        try:
            search_result = search.show(name_or_id)
        except (search.SearchError, socket.error):
            pass
        else:
            use_validated_cache = 'schema' not in context
            if use_validated_cache and 'validated_data_dict' in search_result:
                package_dict = json.loads(search_result['validated_data_dict'])
                package_dict_validated = True
            else:
                package_dict = json.loads(search_result['data_dict'])
                package_dict_validated = False
            metadata_modified = pkg.metadata_modified.isoformat()
            search_metadata_modified = search_result['metadata_modified']
            # solr stores less precice datetime,
            # truncate to 22 charactors to get good enough match
            if metadata_modified[:22] != search_metadata_modified[:22]:
                package_dict = None
    log.debug('debug start')
    if not package_dict:
        package_dict = model_dictize.package_dictize(pkg, context)
        package_dict_validated = False
    log.debug('debug end')
    # Add page-view tracking summary data to the package dict.
    # If the package_dict came from the Solr cache then it will already have a
    # potentially outdated tracking_summary, this will overwrite it with a
    # current one.
    package_dict['tracking_summary'] = model.TrackingSummary.get_for_package(
        package_dict['id'])
    
    for resource_dict in package_dict['resources']:
        _add_tracking_summary_to_resource_dict(resource_dict, model)

    if context.get('for_view'):
        for item in plugins.PluginImplementations(plugins.IPackageController):
            package_dict = item.before_view(package_dict)

    for item in plugins.PluginImplementations(plugins.IPackageController):
        item.read(pkg)

    valid_resources = []
    for resource_dict in package_dict['resources']:
        for item in plugins.PluginImplementations(plugins.IResourceController):
            resource_dict = item.before_show(resource_dict)
            if item.name=='dataset':
                if resource_dict:
                    log.info('adding resource: %s', resource_dict)
                    valid_resources.append(resource_dict)
                else:
                    log.info('skipping resource')
    package_dict['resources'] = valid_resources

    if not package_dict_validated:
        package_plugin = lib_plugins.lookup_package_plugin(package_dict['type'])
        if 'schema' in context:
            schema = context['schema']
        else:
            schema = package_plugin.show_package_schema()
            if schema and context.get('validate', True):
                package_dict, errors = _validate(package_dict, schema,
                    context=context)

    for item in plugins.PluginImplementations(plugins.IPackageController):
        item.after_show(context, package_dict)
    audit_helper(context, data_dict, 'package_show')
    return package_dict

def resource_show(context, data_dict):
    '''Return the metadata of a resource.

    :param id: the id of the resource
    :type id: string

    :rtype: dictionary

    '''
    model = context['model']
    id = _get_or_bust(data_dict, 'id')

    resource = model.Resource.get(id)
    context['resource'] = resource

    if not resource:
        raise NotFound

    _check_access('resource_show', context, data_dict)
    resource_dict = model_dictize.resource_dictize(resource, context)

    _add_tracking_summary_to_resource_dict(resource_dict, model)

    for item in plugins.PluginImplementations(plugins.IResourceController):
        resource_dict = item.before_show(resource_dict)
    
    audit_helper(context, data_dict, 'resource_show')
    return resource_dict

def _add_tracking_summary_to_resource_dict(resource_dict, model):
    '''Add page-view tracking summary data to the given resource dict.

    '''
    tracking_summary = model.TrackingSummary.get_for_resource(
        resource_dict['url'])
    resource_dict['tracking_summary'] = tracking_summary

@ckan.logic.side_effect_free  
@logic.validate(logic.schema.default_resource_search_schema)
def resource_search(context, data_dict):
    '''
    Searches for resources satisfying a given search criteria.

    It returns a dictionary with 2 fields: ``count`` and ``results``.  The
    ``count`` field contains the total number of Resources found without the
    limit or query parameters having an effect.  The ``results`` field is a
    list of dictized Resource objects.

    The 'query' parameter is a required field.  It is a string of the form
    ``{field}:{term}`` or a list of strings, each of the same form.  Within
    each string, ``{field}`` is a field or extra field on the Resource domain
    object.

    If ``{field}`` is ``"hash"``, then an attempt is made to match the
    `{term}` as a *prefix* of the ``Resource.hash`` field.

    If ``{field}`` is an extra field, then an attempt is made to match against
    the extra fields stored against the Resource.

    Note: The search is limited to search against extra fields declared in
    the config setting ``ckan.extra_resource_fields``.

    Note: Due to a Resource's extra fields being stored as a json blob, the
    match is made against the json string representation.  As such, false
    positives may occur:

    If the search criteria is: ::

        query = "field1:term1"

    Then a json blob with the string representation of: ::

        {"field1": "foo", "field2": "term1"}

    will match the search criteria!  This is a known short-coming of this
    approach.

    All matches are made ignoring case; and apart from the ``"hash"`` field,
    a term matches if it is a substring of the field's value.

    Finally, when specifying more than one search criteria, the criteria are
    AND-ed together.

    The ``order`` parameter is used to control the ordering of the results.
    Currently only ordering one field is available, and in ascending order
    only.

    The ``fields`` parameter is deprecated as it is not compatible with calling
    this action with a GET request to the action API.

    The context may contain a flag, `search_query`, which if True will make
    this action behave as if being used by the internal search api.  ie - the
    results will not be dictized, and SearchErrors are thrown for bad search
    queries (rather than ValidationErrors).

    :param query: The search criteria.  See above for description.
    :type query: string or list of strings of the form "{field}:{term1}"
    :param fields: Deprecated
    :type fields: dict of fields to search terms.
    :param order_by: A field on the Resource model that orders the results.
    :type order_by: string
    :param offset: Apply an offset to the query.
    :type offset: int
    :param limit: Apply a limit to the query.
    :type limit: int

    :returns:  A dictionary with a ``count`` field, and a ``results`` field.
    :rtype: dict

    '''
    model = context['model']

    # Allow either the `query` or `fields` parameter to be given, but not both.
    # Once `fields` parameter is dropped, this can be made simpler.
    # The result of all this gumpf is to populate the local `fields` variable
    # with mappings from field names to list of search terms, or a single
    # search-term string.
    query = data_dict.get('query')
    fields = data_dict.get('fields')

    if query is None and fields is None:
        raise ValidationError({'query': _('Missing value')})

    elif query is not None and fields is not None:
        raise ValidationError(
            {'fields': _('Do not specify if using "query" parameter')})

    elif query is not None:
        if isinstance(query, basestring):
            query = [query]
        try:
            fields = dict(pair.split(":", 1) for pair in query)
        except ValueError:
            raise ValidationError(
                {'query': _('Must be <field>:<value> pair(s)')})

    else:
        log.warning('Use of the "fields" parameter in resource_search is '
                            'deprecated.  Use the "query" parameter instead')

        # The legacy fields paramter splits string terms.
        # So maintain that behaviour
        split_terms = {}
        for field, terms in fields.items():
            if isinstance(terms, basestring):
                terms = terms.split()
            split_terms[field] = terms
        fields = split_terms

    order_by = data_dict.get('order_by')
    offset = data_dict.get('offset')
    limit = data_dict.get('limit')

    q = model.Session.query(model.Resource).join(model.ResourceGroup).join(model.Package)
    q = q.filter(model.Package.state == 'active')
    q = q.filter(model.Package.private == False)
    q = q.filter(model.Resource.state == 'active')

    resource_fields = model.Resource.get_columns()
    for field, terms in fields.items():

        if isinstance(terms, basestring):
            terms = [terms]

        if field not in resource_fields:
            msg = _('Field "{field}" not recognised in resource_search.')\
                    .format(field=field)

            # Running in the context of the internal search api.
            if context.get('search_query', False):
                raise search.SearchError(msg)

            # Otherwise, assume we're in the context of an external api
            # and need to provide meaningful external error messages.
            raise ValidationError({'query': msg})

        for term in terms:

            # prevent pattern injection
            term = misc.escape_sql_like_special_characters(term)

            model_attr = getattr(model.Resource, field)

            # Treat the has field separately, see docstring.
            if field == 'hash':
                q = q.filter(model_attr.ilike(unicode(term) + '%'))

            # Resource extras are stored in a json blob.  So searching for
            # matching fields is a bit trickier.  See the docstring.
            elif field in model.Resource.get_extra_columns():
                model_attr = getattr(model.Resource, 'extras')

                like = _or_(
                    model_attr.ilike(u'''%%"%s": "%%%s%%",%%''' % (field, term)),
                    model_attr.ilike(u'''%%"%s": "%%%s%%"}''' % (field, term))
                )
                q = q.filter(like)

            # Just a regular field
            else:
                q = q.filter(model_attr.ilike('%' + unicode(term) + '%'))

    if order_by is not None:
        if hasattr(model.Resource, order_by):
            q = q.order_by(getattr(model.Resource, order_by))

    count = q.count()
    q = q.offset(offset)
    q = q.limit(limit)

    results = []
    for result in q:
        if isinstance(result, tuple) and isinstance(result[0], model.DomainObject):
            # This is the case for order_by rank due to the add_column.
            if toolkit.get_action('is_resource_public')(context, result[0].extras):
                results.append(result[0])
        else:
            if toolkit.get_action('is_resource_public')(context, result.extras):
                results.append(result)

    # If run in the context of a search query, then don't dictize the results.
    if not context.get('search_query', False):
        results = model_dictize.resource_list_dictize(results, context)

    return {'count': count,
            'results': results}


@ckan.logic.side_effect_free
@logic.validate(logic.schema.default_package_list_schema)
def current_package_list_with_resources(context, data_dict):
    '''Return a list of the site's datasets (packages) and their resources.

    The list is sorted most-recently-modified first.

    :param limit: if given, the list of datasets will be broken into pages of
        at most ``limit`` datasets per page and only one page will be returned
        at a time (optional)
    :type limit: int
    :param offset: when ``limit`` is given, the offset to start returning packages from
    :type offset: int
    :param page: when ``limit`` is given, which page to return, Deprecated use ``offset``
    :type page: int

    :rtype: list of dictionaries

    '''
    model = context["model"]
    limit = data_dict.get('limit')
    offset = data_dict.get('offset', 0)

    if not 'offset' in data_dict and 'page' in data_dict:
        log.warning('"page" parameter is deprecated.  '
                    'Use the "offset" parameter instead')
        page = data_dict['page']
        if limit:
            offset = (page - 1) * limit
        else:
            offset = 0

    _check_access('current_package_list_with_resources', context, data_dict)

    query = model.Session.query(model.PackageRevision)
    query = query.filter(model.PackageRevision.state=='active')
    query = query.filter(model.PackageRevision.current==True)
    query = query.filter(model.PackageRevision.private==False)
    
    query = query.order_by(model.package_revision_table.c.revision_timestamp.desc())
    if limit is not None:
        query = query.limit(limit)
    query = query.offset(offset)
    pack_rev = query.all()
    return _package_list_with_resources(context, pack_rev)

def _package_list_with_resources(context, package_revision_list):
    package_list = []
    for package in package_revision_list:
        result_dict = model_dictize.package_dictize(package,context)
        log.info('package resources: %s', result_dict)
        valid_resources = []
        for resource in result_dict['resources']:
            if toolkit.get_action('is_resource_public')(context, resource):
                valid_resources.append(resource)
        result_dict['resources'] = valid_resources    
        package_list.append(result_dict)
    return package_list

@ckan.logic.side_effect_free
def query_changes(context, data_dict):
    '''Query changes of given resource ID since given timestamp in the DataStore.

    .. note:: This action is only available when using PostgreSQL 9.X and using a read-only user on the database.
        It is not available in :ref:`legacy mode<legacy-mode>`.

    :param id: resource id
    :type id: string
    :param changed_since: timestamp, all changes after this date will be listed in results, if not stated, all rows are listed (optional)
    :type changed_since: string or unicode
    :param alias_modified_timestamp: name of column where the timestamp of last modification is defined (default value is 'modified_timestamp') (optional)
    :type alias_modified_timestamp: string
    :param alias_deleted_timestamp: name of column where the timestamp of deletion is defined (default value is 'deleted_timestamp') (optional)
    :type alias_deleted_timestamp: string
    :param limit: limit if returned changes (default value is 100) (optional)
    :type limit: int
    :param offset: if limit given, offset define page where to start (default value is 0) (optional)
    :type offset: int    
    
    **Results:**

    The result of this action is a dictionary with the following keys:

    :rtype: A dictionary with the following keys
    :param fields: fields/columns and their extra metadata
    :type fields: list of dictionaries
    :param records: list of matching results
    :type records: list of dictionaries
    '''
    resource_id = _get_or_bust(data_dict, 'id')
    changed_since = data_dict.get('changed_since', None)
    alias_modified_timestamp = data_dict.get('alias_modified_timestamp', 'modified_timestamp')
    alias_deleted_timestamp = data_dict.get('alias_deleted_timestamp', alias_modified_timestamp)
    limit = data_dict.get('limit', 100)
    offset = data_dict.get('offset', 0)
    sql_query_base = ('SELECT * FROM "{resource_id}" '
                      'ORDER BY {alias_modified_timestamp} ASC '
                      'LIMIT {limit} OFFSET {offset};')
    sql_query_extended = ('SELECT * FROM "{resource_id}" '
                          'WHERE {alias_modified_timestamp}>\'{changed_since}\' OR {alias_deleted_timestamp}>\'{changed_since}\' '
                          'ORDER BY {alias_modified_timestamp} ASC '
                          'LIMIT {limit} OFFSET {offset};')
    sql_query_extended_same = ('SELECT * FROM "{resource_id}" '
                               'WHERE {alias_modified_timestamp}>\'{changed_since}\' '
                               'ORDER BY {alias_modified_timestamp} ASC '
                               'LIMIT {limit} OFFSET {offset};')
    if changed_since:
        if alias_modified_timestamp != alias_deleted_timestamp:
            sql_query = sql_query_extended.format(resource_id=resource_id, changed_since=changed_since,
                                                  alias_modified_timestamp = alias_modified_timestamp,
                                                  alias_deleted_timestamp = alias_deleted_timestamp,
                                                  limit = limit,
                                                  offset = offset)
        else:
            sql_query = sql_query_extended_same.format(resource_id=resource_id, changed_since=changed_since,
                                      alias_modified_timestamp = alias_modified_timestamp,
                                      limit = limit,
                                      offset = offset)
    else:
        sql_query = sql_query_base.format(resource_id=resource_id,
                                          alias_modified_timestamp = alias_modified_timestamp,
                                          limit = limit,
                                          offset = offset)

    datastore_sql_search = toolkit.get_action('datastore_search_sql')
    return datastore_sql_search(data_dict={'sql' : sql_query})
