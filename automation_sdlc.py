"""
automation_sdlc.py
Description: Code Logic to create Epic and associated issues for SDLC Process
"""

import os
import json
import logging
import boto3
import re


from autotechdesk.fresh_service_ticket import initialise_techdesk_object
from awslambda import helpers, errors

from ldap_helper.ldap import ldap, LDAPSearchException

from atlassian_wrapper import messages as msg
from atlassian_wrapper.jira_rest_api import JiraCloudRestAPI
from atlassian_wrapper.atlassian_scim_rest_api import AtlassianRestApiSCIM
from atlassian_wrapper.notification_slack import SlackNotificationAPI


# Logging configuration
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)


# Create an SNS client
SNS = boto3.client('sns')

# Get the SSM Path
AWS_SSM_PATH = os.environ['AWS_COMMON_SSM_PATH']
ENVIRONMENT = os.environ['ENVIRONMENT']
ATL_SSM_PARAMS_PATH = os.environ['AWS_LAMBDA_SSM_PATH']


def check_project_access(jira_project_key, jira_api, user_account_id, access_check):
    """
    Check if user has access to the project
    Args:
        jira_project_key (str): The key of the project to check access for
        jira_api (JiraCloudRestAPI): The Jira API object
        user_account_id (str): The ID of the user to check access for
        access_check (str): The type of access to check for
    Returns:
        bool: True if user has access, False otherwise
    """

    users_group = jira_api.get_user_groups(
        account_id=user_account_id
    ).json()

    user_groups = [group['name'] for group in users_group]

    if access_check == "roles":
        access_levels = ["Developers", "Users", "Administrators"]

        for access_level in access_levels:

            project_role_payload = jira_api.get_project_role_url(
                project_key=jira_project_key,
                project_role=access_level
            )

            project_actors = None

            if project_role_payload:
                project_actors = jira_api.get_project_role_details(
                    project_role_payload
                )

            try:
                users_ids = []

                for actors in project_actors.json()["actors"]:
                    if "actorUser" in actors.keys():
                        users_ids.append(actors["actorUser"]["accountId"])

                if user_account_id in users_ids:
                    return True

            except Exception as err:
                LOGGER.error(
                    "Error in checking access for user %s to project %s. %s",
                    str(user_account_id),
                    str(jira_project_key),
                    str(err)
                )
                return False

            try:
                roles_groups = []

                for actors in project_actors.json()["actors"]:
                    if "actorGroup" in actors.keys():
                        roles_groups.append(actors["actorGroup"]["name"])

                for group in user_groups:
                    if group in roles_groups:
                        return True

            except Exception as err:
                LOGGER.error(
                    "Error in checking access for user %s to project %s. %s",
                    str(user_account_id),
                    str(jira_project_key),
                    str(err)
                )
                return False

        return False
    else:

        if access_check == "scheme_groups":

            response = jira_api.get_project_permissionscheme(
                project_id=jira_project_key,
                q="expand=group"
            ).json()

            create_issue_group = [
                group_details[
                    "holder"
                ]["group"]["name"] for group_details in response[
                    "permissions"
                ] if group_details[
                    "permission"
                ] == "CREATE_ISSUES" and group_details[
                    "holder"
                ].get("group")
            ]

            if create_issue_group:
                for group in user_groups:
                    if group in create_issue_group:
                        return True

            create_issue_applicationrole = [
                group_details[
                    "holder"
                ] for group_details in response[
                    "permissions"
                ] if group_details[
                    "permission"
                ] == "CREATE_ISSUES" and group_details[
                    "holder"
                ]["type"] == "applicationRole"
            ]

            if create_issue_applicationrole:
                return True

    return False


# Function to replace '<system_description>'
def replace_description(data, target, replacement):
    """
    Replace the target string with the replacement string in the data
    Args:
        data (dict or list): The data to replace the target string with the replacement string
        target (str): The target string to replace
        replacement (str): The replacement string
    Returns:
        None
    """
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                replace_description(value, target, replacement)
            elif key == 'text' and value == target:
                data[key] = replacement
    elif isinstance(data, list):
        for item in data:
            replace_description(item, target, replacement)


def replace_all_special_characters(string):
    """
    Replace all special characters in a string with underscore
    Args:
        string (str): The string to replace the special characters with underscore
    Returns:
        str: The string with the special characters replaced with underscore
    """
    special_characters = [
        " ", "-", ".", "(", ")", ":", "/", "?", "!", "'", '"', "&", "%", "#", "@",
        "$", "^", "*", "+", "=", "{", "}", "[", "]", "|", "\\", "<", ">", "`"
    ]

    # Replace each special character with an underscore
    for char in special_characters:
        string = string.replace(char, "_")

    # Remove consecutive underscores
    string = re.sub(r'_+', '_', string)

    # Remove leading or trailing underscores
    string = string.strip('_')

    return string


def generate_payload(
        json_payload,
        user_account_id,
        system_name,
        _fieldset,
        summary_replace=None,
        xtra_payload=None
):
    """
    Generate Issue Payload
    Args:
        json_payload (dict): The JSON payload to generate the issue payload from
        user_account_id (str): The ID of the user to generate the issue payload for
        system_name (str): The name of the system to generate the issue payload for
        _fieldset (list): The fieldset to generate the issue payload for
        xtra_payload (dict): The extra payload to generate the issue payload for
    Returns:
        dict: The generated issue payload
    """

    issues_payload = {
        "update": {},
        "watchers": [user_account_id],
    }

    payload_fields = {}
    

    for field in _fieldset:
        if field == "summary":
            if summary_replace:
                payload_fields[field] = json_payload[field].replace(
                    "<sdlc_year>", summary_replace
                )
                #payload_fields[field] = json_payload[field].replace(
                #   "<sdlc_year_qtr>", summary_replace
                #)
                payload_fields[field] = json_payload[field].replace(
                    "<product_name> <sdlc_year>", summary_replace
                )
            else:
                payload_fields[field] = json_payload[field].replace(
                    "<system_name>", system_name
                )
            sample_field = payload_fields[field]
            LOGGER.info("payload info is %s.", sample_field)

        elif field == "description":

            description_data = json_payload[field]

            replace_description(
                description_data, '<system_description>', ""
            )

            payload_fields[field] = description_data

        elif field == "components":
            payload_fields[field] = [
                {'name': 'SDLC Improvement Process'}
            ]

        elif field == "labels":

            issue_label = json_payload[field][:]

            issue_label.append(
                "prj_" + replace_all_special_characters(
                    system_name.lower()
                )
            )

            payload_fields[field] = issue_label

        else:
            payload_fields[field] = json_payload[field]

    # Update the payload with the extra payload if provided
    if xtra_payload:
        payload_fields.update(xtra_payload)

    issues_payload['fields'] = payload_fields

    return issues_payload


def lambda_handler(event, context):
    """Entrypoint for lambda handler"""

    aws_params = helpers.load_parameters(AWS_SSM_PATH)
    atl_params = helpers.load_parameters(ATL_SSM_PARAMS_PATH)

    ticket_id = json.loads(event['Records'][0]['Sns']['Message'])[
        "TicketID"].lstrip("SR-")

    techdesk_ticket = initialise_techdesk_object(
        event, context, aws_params, ENVIRONMENT
    )

    # Check if we can process the ticket
    if not techdesk_ticket.is_processible(
            expected_catalog_items=[
                "Atlassian - SDLC Improvement Form",
                "Atlassian - Automation Workflow SDLC",
                "Sdlc - Automation Workflow SDLC"
                
            ]
    ):
        return

    # Start the ticket processing
    techdesk_ticket.start_ticket()

    username = techdesk_ticket.requested_item_values[
        'science_domain_username'
    ].strip()

    if username.endswith("@science.regn.net"):
        username, _ = username.split("@")

    try:
        product_organisation = techdesk_ticket.requested_item_values[
            'product_organisation'
        ].strip()

        if product_organisation.lower() == 'Sandbox'.lower():
            product_organisation = atl_params['product_organisation']
    except KeyError:
        product_organisation = "Elsevier"

    jira_project_key = techdesk_ticket.requested_item_values[
        'jira_project_key'
    ].strip().upper()

    # Use the correct system_name field (it exists in the form)
    system_name = techdesk_ticket.requested_item_values.get("product_name", "").strip()
    current_maturity = techdesk_ticket.requested_item_values.get("current_maturity_level", "")
    expected_maturity = techdesk_ticket.requested_item_values.get("target_maturity_level", "")
    sdlc_year = techdesk_ticket.requested_item_values.get("sdlc_year", "").strip()
    # sdlc_quarter = techdesk_ticket.requested_item_values.get("sdlc_quarter", "").strip()
    # current_maturity = int(current_maturity_level)
    # expected_maturity = int(expected_maturity_level)
    LOGGER.info("Type of current maturity is %s.", type(current_maturity))
    LOGGER.info("Type of expected maturity is %s.", type(expected_maturity))
    LOGGER.info("current maturity is %s.", current_maturity)
    LOGGER.info("expected maturity is %s.", expected_maturity)
    LOGGER.info("system name is %s.", system_name)
    LOGGER.info("sdlc year is %s.", sdlc_year)

    if sdlc_year:
         
         sdlc_year = sdlc_year or ""

    summary_composite = ""
    if system_name and sdlc_year:
        summary_composite = f"{system_name} {sdlc_year}"
    elif system_name:
        summary_composite = f"{system_name}"
    elif sdlc_year:
        summary_composite = f"{sdlc_year}"

    techdesk_ticket_url = atl_params['techdesk_ticket_url'].format(
        ticket_id=ticket_id
    )

    # initialization LDAP object
    ldap_client = ldap(
        aws_params['service-account-name'],
        aws_params['service-account-password'],
        aws_params['primary-ldap-endpoint']
    )

    if not helpers.is_valid_username(username):
        LOGGER.error("Invalid username provided: %s", username)
        techdesk_ticket.reply_to_ticket(
            errors.INVALID_USERNAME_ERROR.format(
                username=username,
                catalog_id=techdesk_ticket.get_enquiry_catalog_id(),
                catalog_type=techdesk_ticket.ticket_service
            )
        )
        techdesk_ticket.resolve_ticket()
        return

    try:
        user_dn = ldap_client.get_user(
            username
        )['dn']
    except LDAPSearchException as err:
        LOGGER.error(
            "LDAP Search Error: %s and username: %s. Not able to find user in AD.",
            str(err),
            str(username)
        )
        techdesk_ticket.reply_to_ticket(
            errors.LDAP_USER_NOT_FOUND_ERROR.format(
                username=username,
                catalog_id=techdesk_ticket.get_enquiry_catalog_id(),
                catalog_type=techdesk_ticket.ticket_service
            )
        )
        techdesk_ticket.resolve_ticket()
        return
    else:
        user_mail_id = ldap_client.get_user(username)[
            'attributes'
        ]['mail'][0]

    # Searchbase for Elsevier OU in LDAP
    ldap_client.search_base = aws_params['atlassian-ldap-search-base'].format(
        organization="Elsevier-Atlassian"
    )

    # Fetching LDAP SCIM group to check user is onboarded or not
    ldap_group_name = atl_params['jira_ldap_group_name']

    # Searching the group in LDAP
    try:
        all_users_group_member = ldap_client.get_group(
            ldap_group_name
        )['attributes']['member']
    except LDAPSearchException:
        techdesk_ticket.reply_to_ticket(
            errors.LDAP_GROUP_NOT_FOUND_ERROR.format(
                group=ldap_group_name,
                catalog_id=techdesk_ticket.get_enquiry_catalog_id(),
                catalog_type=techdesk_ticket.ticket_service
            )
        )
        techdesk_ticket.resolve_ticket()
        return

    if user_dn not in all_users_group_member:
        LOGGER.error(
            "User %s is not having jira product access on %s Org.",
            str(username), str(product_organisation)
        )

        techdesk_ticket.reply_to_ticket(
            msg.ATL_USER_NOT_ADDED.format(

                username=username,
                atlassian_product="Jira",
                onboard_offboard_user_form=atl_params[
                    'techdesk_catalog_url'
                ].format(
                    catelog_id=msg.atlassian_techDesk_templates[
                        'onboard_offboard_template_id'
                    ]
                ),
                onboard_offboard_user_form_name="Atlassian - Jira and Confluence Product Access"
            )
            + errors.CONDITIONAL_CONTACT_SECTION.format(
                catalog_id=techdesk_ticket.get_enquiry_catalog_id(),
                catalog_type=techdesk_ticket.ticket_service
            )
        )
        techdesk_ticket.resolve_ticket()
        return

    # jira api object initialization
    jira_api = JiraCloudRestAPI(
        auth_email=atl_params['atlassian-rest-api-user'],
        auth_token=atl_params['atlassian-rest-api-user-token'],
        endpoint=atl_params['atlassian-rest-api-endpoint']
    )

    # scim api object initialization
    scim_api = AtlassianRestApiSCIM(
        atl_params['atlassian-user-prov-apikey'],
        atl_params['atlassian-user-prov-dirkey']
    )

    slack_api = SlackNotificationAPI(aws_params['slack-notification'])

    account_id_search = scim_api.get_account_detail(
        science_domain_user=username
    )

    try:
        user_account_id = account_id_search.json()[
            'Resources'][0]['urn:scim:schemas:extension:atlassian-external:1.0'
                            ]['atlassianAccountId']
    except Exception as err:
        LOGGER.error(
            "Unable to locate user %s in Atlassian SCIM profile. %s",
            str(username),
            str(err)
        )

        techdesk_ticket.reply_to_ticket(
            (
                f"Unable to locate user {username}({user_mail_id}) in Atlassian SCIM profile. "
                "Please wait for 2 hours for the profile to sync with Atlassian and Azure AD, "
                "and try again."
            ) +
            "</br></br>"
            + errors.CONDITIONAL_CONTACT_SECTION.format(
                catalog_id=techdesk_ticket.get_enquiry_catalog_id(),
                catalog_type=techdesk_ticket.ticket_service
            )
        )
        techdesk_ticket.resolve_ticket()
        return
    else:
        if not user_account_id:
            LOGGER.error(
                "Unable to locate user %s in Atlassian SCIM profile. ",
                str(username)
            )
            techdesk_ticket.reply_to_ticket(
                (
                    f"Unable to locate user {username}({user_mail_id}) in Atlassian SCIM profile. "
                    "Please wait for 2 hours for the profile to sync with Atlassian and Azure AD, "
                    "and try again."
                ) +
                "</br></br>"
                + errors.CONDITIONAL_CONTACT_SECTION.format(
                    catalog_id=techdesk_ticket.get_enquiry_catalog_id(),
                )
            )
            techdesk_ticket.resolve_ticket()
            return

    # Checking if project is avcailable with same key provided
    project_detail = jira_api.get_project_details(
        project_key=jira_project_key
    )

    if project_detail.status_code != 200:
        LOGGER.info(
            "Not able to find the project with associated key: %s.",
            str(jira_project_key)
        )

        techdesk_ticket.reply_to_ticket(
            (
                f"We are unable to locate the project with the provided key {jira_project_key}. "
                "We kindly suggest that you resubmit the request with the correct project key."
            ) +
            "</br></br>"
            + errors.CONDITIONAL_CONTACT_SECTION.format(
                catalog_id=techdesk_ticket.get_enquiry_catalog_id(),
                catalog_type=techdesk_ticket.ticket_service
            )

        )
        techdesk_ticket.resolve_ticket()
        return

    try:
        filename = "configuration.json"

        if ENVIRONMENT.lower() == "prod":
            filename = "prod_configuration.json"

        with open(filename, encoding="utf-8") as file:
            _conf = json.load(file)

    except FileNotFoundError as e:
        LOGGER.error('Configuration file not found.')

        slack_api.custom_jira_notification(
            requested_for="Error: Atlassian - SDLC process creation",
            link_dict_payload={
                "Techdesk Ticket": {
                    "url": techdesk_ticket_url,
                    "number": ticket_id
                }
            },
            body_dict_payload={
                "Error Description": str(e) + "\nCheck the AWS Cloudwatch logs for more information."
            },
            message="Jira SDLC process creation has failed due to configuration file not found.",
        )
        return

    project_category = project_detail.json().get("projectCategory", {}).get("name")
    project_name = project_detail.json().get("name")
    project_id = project_detail.json().get("id")
    project_issue_types = project_detail.json().get('issueTypes', [])

    if project_category not in _conf["approved_categories"]:
        LOGGER.info(
            "Project %s does not fall under Technology/Approved project categories.",
            str(jira_project_key)
        )

        techdesk_ticket.reply_to_ticket(

            (
                f"Project {project_name} does not fall under Technology/Approved project categories. "
                "Please select the correct project for the Technology Project Review request."
                "</br></br>"
                "<strong>Approved Categories/Business Units:</strong></br>"
                "{approved_categories}"
            ).format(
                approved_categories='</br>'.join(
                    _conf['approved_categories'])
            )
            +
            "</br></br>"
            + errors.CONDITIONAL_CONTACT_SECTION.format(
                catalog_id=techdesk_ticket.get_enquiry_catalog_id(),
                catalog_type=techdesk_ticket.ticket_service
            )
        )

        techdesk_ticket.resolve_ticket()
        return

    # validate work items availability in the project
    issue_types_ids = list()  # list of issue types that are available in the project
    issue_types = _conf['issuetypes']

    for issue_type in project_issue_types:
        if issue_type['name'] in issue_types:
            issue_types_ids.append(
                {
                    "id": issue_type['id'],
                    "name": issue_type['name']
                }
            )

    if len(issue_types_ids) < len(issue_types):
        LOGGER.error(
            "Project %s does not have all the issue types available. %s",
            str(jira_project_key),
            str(issue_types_ids)
        )

        techdesk_ticket.reply_to_ticket(
            (
                f"Unable to get all the issue types for project <strong>{project_name}</strong>. "
                "Please ensure that the issue types are correctly configured in Jira. "
                "If you need assistance, please contact your Jira administrator."
                "</br></br>"
                "<strong>Issue types are mandatory for this operation:</strong></br> "
                f"{'</br>'.join(_conf['issuetypes'])}."
            ) +
            "</br>" +
            (
                "<strong>Project contains below Issue Types:</strong></br>"
                f"{'</br>'.join([issue_type['name'] for issue_type in issue_types_ids])}"
            ) +
            "</br></br>" +
            errors.CONDITIONAL_CONTACT_SECTION.format(
                catalog_id=techdesk_ticket.get_enquiry_catalog_id(),
                catalog_type=techdesk_ticket.ticket_service
            )
        )

        techdesk_ticket.resolve_ticket()
        return

    mandatory_fields = _conf.get('mandatory_fields', [])

    if not mandatory_fields:
        LOGGER.info(
            "No mandatory fields are configured for the project %s.",
            str(project_name)
        )

        return

    for issuetype_id in issue_types_ids:
        LOGGER.info(
            "Processing issue type ID: %s for project: %s",
            issuetype_id.get('name'),
            str(project_name)
        )

        field_metadata_details = jira_api.get_createfield_metadata_project_issuetype(
            project_key=project_id,
            issuetype_id=issuetype_id.get('id') + "?maxResults=120"
        )

        fields = [
            field for field in field_metadata_details.json().get("fields", []) if field['key'] in mandatory_fields
        ]

        if len(fields) < len(mandatory_fields):

            LOGGER.info(
                "Unable to get all the mandatory fields for issue type %s in project: %s.",
                str(issuetype_id.get('name')),
                str(project_name)
            )

            missing_fields = set(mandatory_fields) - set(
                [field['key'] for field in fields]
            )

            techdesk_ticket.reply_to_ticket(
                (
                    "Unable to get all the mandatory fields for issue type: "
                    f"<strong>{issuetype_id.get('name')}</strong> in project: "
                    f"<strong>{project_name}</strong>. </br>"
                    "Please ensure that the mandatory fields are correctly configured in Jira. "
                    "If you need assistance, please contact your Jira administrator."
                    "</br>"
                    "<strong>Mandatory fields are:</strong> "
                    f"{'</br>'.join(mandatory_fields)}."
                    "</br>"
                    "<strong>Missing fields are:</strong> "
                    f"{'</br>'.join(missing_fields)}."
                ).replace("customfield_17443", "Activity Type")
                +
                "</br></br>" +
                errors.CONDITIONAL_CONTACT_SECTION.format(
                    catalog_id=techdesk_ticket.get_enquiry_catalog_id(),
                    catalog_type=techdesk_ticket.ticket_service
                )
            )

            techdesk_ticket.resolve_ticket()
            return

        LOGGER.info(
            "All mandatory fields are present for issue type %s in project: %s.",
            str(issuetype_id.get('name')),
            str(project_name)
        )

    is_authorized = False

    if check_project_access(
        jira_project_key=jira_project_key,
        jira_api=jira_api,
        user_account_id=user_account_id,
        access_check="roles"
    ):
        is_authorized = True

    if not is_authorized:
        if check_project_access(
            jira_project_key=jira_project_key,
            jira_api=jira_api,
            user_account_id=user_account_id,
            access_check="scheme_groups"
        ):
            is_authorized = True

    if not is_authorized:
        LOGGER.info(
            "User %s is not having access to the project %s.",
            str(username), str(jira_project_key)
        )
        techdesk_ticket.reply_to_ticket(
            f"User {username} is not having access to the project {jira_project_key}. " +
            "Please raise a request to get access to the project and try again."
            +
            "</br></br>"
            + errors.CONDITIONAL_CONTACT_SECTION.format(
                catalog_id=techdesk_ticket.get_enquiry_catalog_id(),
                catalog_type=techdesk_ticket.ticket_service
            )
        )
        techdesk_ticket.resolve_ticket()
        return

    try:
        sdlc_initiative = _conf["sdlc_initiative"]
        sdlc_counter = 0

        for initiative_id in sdlc_initiative:  # Looping through the Epic to be created
            initiative_detail = jira_api.get_issue_detail(
                issue_key=initiative_id
            )

            sdlc_counter = sdlc_counter + 1

            extra_payload = {
                "project": {
                    "id": project_id
                },
                "reporter": {
                    "id": user_account_id
                },
                "assignee": {
                    "id": user_account_id
                }
            }

            if initiative_detail.status_code != 200:
                LOGGER.error(
                    "Not able to find the template initiative with key: %s.",
                    str(initiative_id)
                )

                LOGGER.error(
                    "Error in creating Jira SDLC process Request: %s",
                    str(initiative_detail.json())
                )

                slack_api.custom_jira_notification(
                    requested_for="Error: Atlassian - SDLC process creation",
                    link_dict_payload={
                        "Techdesk Ticket": {
                            "url": techdesk_ticket_url,
                            "number": ticket_id
                        }
                    },
                    body_dict_payload={
                        "Error Description": str(initiative_detail.json()) + "\nCheck the AWS Cloudwatch logs for more information."
                    },
                    message="Jira SDLC process creation has failed due to template initiative not found.",
                )
                return

            LOGGER.info(
                "Proceeding to create Initiative %s for the project %s.",
                str(initiative_id), str(jira_project_key)
            )

            initiative_payload_json = initiative_detail.json().get('fields')

            initiative_issue_payload = generate_payload(
                json_payload=initiative_payload_json,
                user_account_id=user_account_id,
                system_name=system_name,
                _fieldset=_conf['mandatory_fields'],
                xtra_payload=extra_payload,
                summary_replace=summary_composite if summary_composite else None
            )

            LOGGER.info(
                "Creating Initiative %s for the project %s.",
                str(initiative_id), str(jira_project_key)
            )

            created_initiative_detail = jira_api.create_jira_issue(
                issue_payload=initiative_issue_payload
            )

            if created_initiative_detail.status_code != 201:
                LOGGER.error(
                    "Not able to create the initiative for the project %s.",
                    str(jira_project_key)
                )

                LOGGER.error(
                    "Error in creating sdlc process Request: %s",
                    str(created_initiative_detail.json())
                )

                slack_api.custom_jira_notification(
                    requested_for="Error: Atlassian - SDLC process creation",
                    link_dict_payload={
                        "Techdesk Ticket": {
                            "url": techdesk_ticket_url,
                            "number": ticket_id
                        }
                    },
                    body_dict_payload={
                        "Error Description": str(created_initiative_detail.json()) + "\nCheck the AWS Cloudwatch logs for more information."
                    },
                    message="Jira sdlc process creation has failed due to initiative creation failed.",
                )
                return

            created_initiative_id = created_initiative_detail.json()['id']
            created_initiative_key = created_initiative_detail.json()['key']

            LOGGER.info(
                "Initiative %s has been created successfully for the project %s.",
                str(created_initiative_key), str(jira_project_key)
            )

            _product_url = "https://{product_organisation}.atlassian.net/jira/software/c/projects".format(
                product_organisation=product_organisation.lower()
            )

            issue_url = "{_product_url}/{jira_project_key}/issues/{initiative_key}".format(
                _product_url=_product_url,
                jira_project_key=jira_project_key,
                initiative_key=created_initiative_key
            )

            LOGGER.info(
                "Searching for all the epics associated with initiative."
            )

            associated_epics = jira_api.get_associated_issues_using_jql(
                jql=f"parent = {initiative_id} ORDER BY created ASC",
                fields=",".join(_conf['mandatory_fields'])
            )

            if associated_epics.status_code != 200:
                LOGGER.error(
                    "Not able to find the associated epics with the initiative %s.",
                    str(initiative_id)
                )

                LOGGER.error(
                    "Error in creating sdlc process Request: %s",
                    str(associated_epics.json())
                )

                slack_api.custom_jira_notification(
                    requested_for="Error: Atlassian - SDLC process creation",
                    link_dict_payload={
                        "Techdesk Ticket": {
                            "url": techdesk_ticket_url,
                            "number": ticket_id
                        }
                    },
                    body_dict_payload={
                        "Error Description": str(associated_epics.json()) + "\nCheck the AWS Cloudwatch logs for more information."
                    },
                    message="Jira SDLC process creation has been failed due to associated epics not found.",
                )
                return

            LOGGER.info(
                "Proceeding to create epics for the project underneath SDLC initiative."
            )

            try:
                associated_epics_detail = associated_epics.json()['issues']
                for epic in associated_epics_detail:

                    extra_payload.update(
                        {
                            "parent": {
                                "id": created_initiative_id
                            }
                        }
                    )

                    epic_payload_json = epic.get('fields')
                    template_epic_key = epic.get('key')

                    epic_issue_payload = generate_payload(
                        json_payload=epic_payload_json,
                        user_account_id=user_account_id,
                        system_name=system_name,
                        _fieldset=_conf['mandatory_fields'],
                        xtra_payload=extra_payload
                    )

                    created_epic = jira_api.create_jira_issue(
                        issue_payload=epic_issue_payload
                    )

                    if created_epic.status_code != 201:
                        LOGGER.error(
                            "Not able to create epic for the project %s.",
                            str(jira_project_key)
                        )
                        LOGGER.error(
                            "Error in creating Jira SDLC process Request: %s",
                            str(created_epic.json())
                        )

                        slack_api.custom_jira_notification(
                            requested_for="Error: Atlassian - SDLC process creation",
                            link_dict_payload={
                                "Techdesk Ticket": {
                                    "url": techdesk_ticket_url,
                                    "number": ticket_id
                                }
                            },
                            body_dict_payload={
                                "Error Description": str(created_epic.json()) + "\nCheck the AWS Cloudwatch logs for more information."
                            },
                            message="Jira SDLC process creation has been failed due to epic creation failed.",
                        )
                        return

                    created_epic_id = created_epic.json()['id']

                    LOGGER.info(
                        "Searching for the issue types for the project underneath SDLC initiative."
                    )

                    issue_types_id = None

                    for issuetype in project_detail.json().get('issueTypes'):
                        if issuetype['name'] == 'Story':
                            issue_types_id = issuetype['id']
                            break

                    if not issue_types_id:
                        LOGGER.error(
                            "Not able to find the issue type 'Story' for the project %s.",
                            str(jira_project_key)
                        )

                        slack_api.custom_jira_notification(
                            requested_for="Error: Atlassian - SDLC process creation",
                            link_dict_payload={
                                "Techdesk Ticket": {
                                    "url": techdesk_ticket_url,
                                    "number": ticket_id
                                }
                            },
                            body_dict_payload={
                                "Error Description": "Issue type 'Story' not found for the project.",
                            },
                            message="Jira SDLC process creation has been failed due to issue type 'Story' not found.",
                        )
                        return

                    LOGGER.info(
                        "Fetching the mandatory fields for the project."
                    )

                    field_metadata_details = jira_api.get_createfield_metadata_project_issuetype(
                        project_key=jira_project_key,
                        issuetype_id=issue_types_id + "?maxResults=120"
                    )

                    mandatory_fields = []

                    for field in field_metadata_details.json()['fields']:
                        if field['required'] and field['key'] not in ['project', 'reporter', 'summary', 'issuetype']:
                            mandatory_fields.append(field)

                    _stories_mand_field = {}

                    for _f in mandatory_fields:
                        if _f['schema']['custom'].endswith('textarea'):
                            _stories_mand_field[_f[
                                'key']
                            ] = _conf[
                                'mandatory_fields_values'
                            ][_f['schema']['custom']]
                        else:
                            _stories_mand_field[_f[
                                'key']
                            ] = _conf[
                                'mandatory_fields_values'
                            ][_f['schema']['type']]

                    LOGGER.info(
                        "Searching for all the issues associated with epic."
                    )

                    associated_stories = jira_api.get_associated_issues_using_jql(
                        jql=f"parent = {template_epic_key} ORDER BY created ASC",
                        fields=",".join(_conf['mandatory_fields'])
                    )

                    if associated_stories.status_code != 200:
                        LOGGER.error(
                            "Not able to find the associated stories with the epic %s.",
                            str(template_epic_key)
                        )

                        LOGGER.error(
                            "Error in creating sdlc process Request: %s",
                            str(associated_stories.json())
                        )

                        slack_api.custom_jira_notification(
                            requested_for="Error: Atlassian - SDLC process creation",
                            link_dict_payload={
                                "Techdesk Ticket": {
                                    "url": techdesk_ticket_url,
                                    "number": ticket_id
                                }
                            },
                            body_dict_payload={
                                "Error Description": str(associated_stories.json()) + "\nCheck the AWS Cloudwatch logs for more information."
                            },
                            message="Jira SDLC process creation has been failed due to associated stories not found.",
                        )
                        return

                    LOGGER.info(
                        "Proceeding to create the stories for the project underneath SDLC epic."
                    )

                    try:
                        associated_stories_detail = associated_stories.json()['issues']
                        for story in associated_stories_detail:

                            extra_payload.update(
                                {
                                    "parent": {
                                        "id": created_epic_id
                                    }
                                }
                            )

                            story_payload_json = story.get('fields')
                            template_story_key = story.get('key')

                            story_issue_payload = generate_payload(
                                json_payload=story_payload_json,
                                user_account_id=user_account_id,
                                system_name=system_name,
                                _fieldset=_conf['mandatory_fields'],
                                xtra_payload={
                                    **extra_payload, **_stories_mand_field
                                }
                            )

                            created_story = jira_api.create_jira_issue(
                                issue_payload=story_issue_payload
                            )

                            if created_story.status_code != 201:
                                LOGGER.error(
                                    "Not able to create the story for the project %s.",
                                    str(jira_project_key)
                                )
                                LOGGER.error(
                                    "Error in creating Jira SDLC process Request: %s",
                                    str(created_story.json())
                                )

                                slack_api.custom_jira_notification(
                                    requested_for="Error: Atlassian - SDLC process creation",
                                    link_dict_payload={
                                        "Techdesk Ticket": {
                                            "url": techdesk_ticket_url,
                                            "number": ticket_id
                                        }
                                    },
                                    body_dict_payload={
                                        "Error Description": str(created_story.json()) + "\nCheck the AWS Cloudwatch logs for more information."
                                    },
                                    message="Jira SDLC process creation has been failed due to story creation failed.",
                                )
                                return

                            created_story_id = created_story.json()['id']

                            LOGGER.info(
                                "Searching for all the task associated with story."
                            )

                            template_project = _conf['template_project']

                            associated_subtasks = jira_api.get_associated_issues_using_jql(
                                jql=f'project = {template_project} and parent = {template_story_key} and "cf[10002]" >= {current_maturity} and "cf[10002]" <= {expected_maturity} ORDER BY created ASC',
                                fields=",".join(_conf['mandatory_fields'])
                            )
                            # LOGGER.info("Associated subtasks are %s.", str(associated_subtasks.json()))

                            if associated_subtasks.status_code != 200:
                                LOGGER.error(
                                    "Not able to find the associated subtasks with the story %s.",
                                    str(template_story_key)
                                )

                                LOGGER.error(
                                    "Error in creating Jira SDLC process creation Request: %s",
                                    str(associated_subtasks.json())
                                )

                                slack_api.custom_jira_notification(
                                    requested_for="Error: Atlassian - SDLC process creation",
                                    link_dict_payload={
                                        "Techdesk Ticket": {
                                            "url": techdesk_ticket_url,
                                            "number": ticket_id
                                        }
                                    },
                                    body_dict_payload={
                                        "Error Description": str(associated_subtasks.json()) + "\nCheck the AWS Cloudwatch logs for more information."
                                    },
                                    message="Jira SDLC process creation Request has been failed due to associated substask not found.",
                                )
                                return

                            LOGGER.info(
                                "Proceeding to create the subtask for the project underneath TPR story."
                            )

                            try:

                                extra_payload.update(
                                    {
                                        "parent": {
                                            "id": created_story_id
                                        }
                                    }
                                )

                                for task in associated_subtasks.json()['issues']:

                                    task_payload_json = task.get('fields')

                                    task_issue_payload = generate_payload(
                                        json_payload=task_payload_json,
                                        user_account_id=user_account_id,
                                        system_name=system_name,
                                        _fieldset=_conf['mandatory_fields'],
                                        xtra_payload=extra_payload
                                    )

                                    created_task = jira_api.create_jira_issue(
                                        issue_payload=task_issue_payload
                                    )

                                    if created_task.status_code != 201:
                                        LOGGER.error(
                                            "Not able to create the task for the project %s.",
                                            str(jira_project_key)
                                        )

                                        LOGGER.error(
                                            "Error in creating Jira SDLC process creation Request: %s",
                                            str(created_task.json())
                                        )

                                        slack_api.custom_jira_notification(
                                            requested_for="Error: Atlassian - SDLC process creation",
                                            link_dict_payload={
                                                "Techdesk Ticket": {
                                                    "url": techdesk_ticket_url,
                                                    "number": ticket_id
                                                }
                                            },
                                            body_dict_payload={
                                                "Error Description": str(created_task.json()) + "\nCheck the AWS Cloudwatch logs for more information."
                                            },
                                            message="Jira SDLC process creation Request has been failed due to task creation failed.",
                                        )
                                        return

                            except Exception as e:
                                LOGGER.error(
                                    "Error while creating Jira SDLC process creation subtask: %s",
                                    str(e)
                                )

                                slack_api.custom_jira_notification(
                                    requested_for="Error: Atlassian - SDLC process creation",
                                    link_dict_payload={
                                        "Techdesk Ticket": {
                                            "url": techdesk_ticket_url,
                                            "number": ticket_id
                                        }
                                    },
                                    body_dict_payload={
                                        "Error Description": str(e) + "\nCheck the AWS Cloudwatch logs for more information."
                                    },
                                    message="SDLC process creation Request has been failed while creating the subtask.",
                                )
                                return

                    except Exception as e:
                        LOGGER.error(
                            "Error while creating Jira SDLC process stories: %s",
                            str(e)
                        )

                        slack_api.custom_jira_notification(
                            requested_for="Error: Atlassian - SDLC process creation",
                            link_dict_payload={
                                "Techdesk Ticket": {
                                    "url": techdesk_ticket_url,
                                    "number": ticket_id
                                }
                            },
                            body_dict_payload={
                                "Error Description": str(e) + "\nCheck the AWS Cloudwatch logs for more information."
                            },
                            message="Jira SDLC process creation has been failed while creating the stories.",
                        )
                        return

                    # techdesk_ticket.reply_to_ticket(
                    #     f"Initiative and all the associated issues related to SDLC-{sdlc_counter} has been created successfully." +
                    #     "Please find the details below:</br></br>" +
                    #     f"<strong>Project:</strong> {project_name}</br>" +
                    #     f"<strong>Project Key:</strong> {jira_project_key}</br>" +
                    #     f"""
                    #     <strong> Initiative Url: </strong> <a href = '{issue_url}' > {created_initiative_key} </a>
                    #     """
                    #     + "</br></br>"
                    #     + errors.CONDITIONAL_CONTACT_SECTION.format(
                    #         catalog_id=techdesk_ticket.get_enquiry_catalog_id(),
                    #         catalog_type=techdesk_ticket.ticket_service
                    #     )
                    # )
                    
            except Exception as e:
                LOGGER.error(
                    "Error while creating Jira SDLC process creation epic: %s",
                    str(e)
                )

                slack_api.custom_jira_notification(
                    requested_for="Error: Atlassian - SDLC process creation",
                    link_dict_payload={
                        "Techdesk Ticket": {
                            "url": techdesk_ticket_url,
                            "number": ticket_id
                        }
                    },
                    body_dict_payload={
                        "Error Description": str(e) + "\nCheck the AWS Cloudwatch logs for more information."
                    },
                    message="SDLC process creation Request has been failed while creating the epic.",
                )
                return

        techdesk_ticket.reply_to_ticket(
            "All the Initiative (including epics, stories and sub-tasks) related to SDLC has been processed successfully." +
            "Please find the details below:</br></br>" +
            f"<strong>Project:</strong> {project_name}</br>" +
            f"<strong>Project Key:</strong> {jira_project_key}</br>" +
            f"""
            <strong> Initiative Url: </strong> <a href = '{issue_url}' > {created_initiative_key} </a>
            """
            "</br></br>"
            + errors.CONDITIONAL_CONTACT_SECTION.format(
                catalog_id=techdesk_ticket.get_enquiry_catalog_id(),
                catalog_type=techdesk_ticket.ticket_service
            )
        )

        LOGGER.info(
            "All the Initiative (including epics, stories and sub-tasks) related to SDLC has been processed successfully."
        )
        LOGGER.info(
            "Updating the Techdesk ticket with the created Initiative tags."
        )

        get_ticket_information = techdesk_ticket.get_all_ticket_information(
            embedded_resource="tags"
        )

        tags = get_ticket_information.get("ticket", {}).get("tags", [])
        tags.append("sdlc_initiative_created")

        techdesk_ticket.update_ticket_information(
            ticket_data={"tags": tags}
        )

        techdesk_ticket.resolve_ticket()

        return

    except Exception as err:
        LOGGER.error(
            "Error while creating Jira SDLC process Request: %s",
            str(err)
        )

        slack_api.custom_jira_notification(
            requested_for="Error: Atlassian - SDLC process creation",
            link_dict_payload={
                "Techdesk Ticket": {
                    "url": techdesk_ticket_url,
                    "number": ticket_id
                }
            },
            body_dict_payload={
                "Error Description": str(err) + "\nCheck the AWS Cloudwatch logs for more information."
            },
            message="Jira SDLC process creation has been failed due to some internal error.",
        )
        return