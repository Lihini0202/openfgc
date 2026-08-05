/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

const commonEn = {
  app: {
    title: 'Consent Portal',
  },
  sidebar: {
    ariaLabel: 'Primary navigation',
    adminAriaLabel: 'Admin navigation',
    dashboard: 'Dashboard',
    consent: 'Consent',
    allConsents: 'All Consents',
    pendingConsents: 'Pending Consents',
    nominations: 'Nominations',
    admin: 'Admin',
    nomineeActivation: 'Nominee Activation',
  },
  layout: {
    home: 'Home',
    breadcrumbAriaLabel: 'Breadcrumb',
    userAvatarAriaLabel: 'Signed-in user avatar',
    signedOutMessage: 'Sign in to view this page.',
    profileMenu: {
      editProfile: 'Edit Profile',
      settings: 'Settings',
      logout: 'Logout',
      login: 'Login',
      signUp: 'Sign Up',
    },
  },
  dashboard: {
    title: 'Dashboard',
  },
  consentRegistry: {
    title: 'All Consents',
    details: {
      title: 'Consent Details',
      clientName: 'Client Name',
      consentId: 'Consent ID',
      status: 'Status',
      type: 'Consent Type',
      frequency: 'Access Limit',
      frequencyHelp: 'This indicates how many times this consent can be accessed per day.',
      frequencyUnitSingular: 'time per day',
      frequencyUnitPlural: 'times per day',
      purposes: 'Purposes',
      duration: 'Lookback Period',
      durationHelp:
        'This defines how far back data can be accessed. For example, if set to 6 months, data from up to 6 months ago is accessible.',
      durationUnitHourSingular: 'hour',
      durationUnitHourPlural: 'hours',
      durationUnitDaySingular: 'day',
      durationUnitDayPlural: 'days',
      durationUnitYearSingular: 'year',
      durationUnitYearPlural: 'years',
      created: 'Created',
      updated: 'Updated',
      validUntil: 'Valid Until',
      clientId: 'Client ID',
      recurring: 'Recurring',
      back: 'Back to Registry',
      notFound: 'Consent record not found',
      approved: 'Approved',
      notApproved: 'Not approved',
      approvedCount: '{{approved}}/{{total}} approved',
      section: {
        purposes: 'Consent Purposes',
        authorizations: 'Authorizations',
        lifecycle: 'Consent Lifecycle',
      },
      table: {
        element: 'Element',
        approved: 'Approved',
        required: 'Required',
        description: 'Description',
        user: 'User',
        status: 'Status',
        updated: 'Updated',
        resources: 'Resources',
        eventType: 'Event Type',
        date: 'Date',
        time: 'Time',
      },
      actions: {
        viewResources: 'View Resources',
        noResourcesTooltip: 'No resources available',
      },
      resourcesModal: {
        title: 'Authorization Resources',
        authRef: 'Auth',
        close: 'Close',
      },
      values: {
        yes: 'Yes',
        no: 'No',
        required: 'Required',
        optional: 'Optional',
      },
    },
    actions: {
      view: 'View',
      revoke: 'Revoke',
      approve: 'Approve',
    },
    modals: {
      consentId: 'Consent ID',
      actions: {
        cancel: 'Cancel',
        processing: 'Processing...',
      },
      approval: {
        title: 'Review & Approve Consent',
        subtitle: 'Please review the consent elements before approval.',
        mandatory: 'Mandatory Elements (Required)',
        optional: 'Optional Elements',
        required: 'Required',
        toggle: 'Toggle permission',
        toggleWithDetails: 'Toggle permission for {{elementName}} in {{purposeName}}',
        loading: 'Loading consent details...',
        noMandatory: 'No mandatory requirements for this consent.',
        confirm: 'Approve & Continue',
      },
      revocation: {
        title: 'Confirm Revocation',
        message: 'Are you sure you want to revoke consent?',
        note: 'This action revokes both mandatory and optional consents granted for all associated purposes.',
        confirm: 'Revoke Consents',
        cancel: 'Cancel',
      },
    },
    status: {
      all: 'All',
      active: 'Active',
      pending: 'Pending',
      created: 'Created',
      approved: 'Approved',
      rejected: 'Rejected',
      revoked: 'Revoked',
      expired: 'Expired',
      systemExpired: 'System Expired',
      systemRevoked: 'System Revoked',
    },
    filters: {
      sectionAriaLabel: 'Consent filters',
      status: 'Status',
      startDate: 'Start date',
      startDateAriaLabel: 'Start date filter',
      endDate: 'End date',
      endDateAriaLabel: 'End date filter',
      consentType: 'Consent type',
      clear: 'Clear',
      clearAriaLabel: 'Clear all filters',
    },
    messages: {
      loading: 'Loading consents...',
      loadFailed: 'Unable to load consents right now.',
      empty: 'No consents found for the selected filters.',
    },
    table: {
      tableAriaLabel: 'Consent registry table',
      clientLabel: 'Client: {{client}}',
      notApplicable: 'Not applicable',
      purposes: {
        more: '+{{count}} more',
        title: 'Consent purposes',
        hint: 'Showing all purposes of the consent',
      },
      headers: {
        consentId: 'Consent ID',
        type: 'Type',
        status: 'Status',
        purposes: 'Purposes',
        updated: 'Updated',
        expiration: 'Expiration',
        actions: 'Actions',
      },
    },
  },
  nominee: {
    title: 'Nominations',
    messages: {
      loadFailed: 'Unable to load nominations right now.',
    },
    status: {
      active: 'Active',
      waiting: 'Waiting',
    },
    myNominee: {
      title: 'My Nominee',
      empty: "You haven't nominated anyone to manage your consents yet.",
      add: 'Add Nominee',
      change: 'Change',
      remove: 'Remove',
      nominatedOn: 'Nominated: {{date}}',
    },
    nominatedFor: {
      title: 'Assigned Accounts',
      empty: 'No accounts have been assigned to you to manage.',
      manage: "Manage {{name}}'s Consents →",
      openAccount: 'Open account →',
      accept: 'Accept',
    },
    acting: {
      banner: 'You are viewing account {{ownerId}} as their nominee',
      allowed: 'You can: {{list}}',
      exit: 'Exit nominee view',
      starting: 'Opening the account…',
      startFailed: 'You are not a nominee for this account.',
      startFailedHint: 'Return to Nominations and try again.',
      blockedTitle: 'Not available in nominee access',
      blockedFenced:
        'Account settings, credentials and nominations can never be used on behalf of another person.',
      blockedScope: 'The owner did not grant you permission for this area.',
      backToAllowed: 'Go to what I can access',
    },
    permissions: {
      consentView: 'View consents',
      consentRevoke: 'Revoke consents',
      accountView: 'View account',
      accountUpdate: 'Update account',
      dataDownload: 'Download data',
      accountDelete: 'Delete account',
    },
    mine: {
      title: 'My Nominee',
      subtitle: 'The person you authorise to act for you. You choose what they may do.',
      add: 'Add Nominee',
      change: 'Change Nominee',
      edit: 'Edit',
      remove: 'Remove',
      empty: "You haven't nominated anyone yet.",
      status: {
        active: 'Active',
        accepted: 'Accepted',
        pending: 'Awaiting acceptance',
        deactivated: 'Deactivated',
      },
    },
    setup: {
      dialog: {
        title: 'Add Nominee',
        subtitle: 'The nominee must already be a registered portal user.',
        editTitle: 'Edit Nominee',
        saveChanges: 'Save Changes',
        emailLabel: "Nominee's registered email",
        nicLabel: "Nominee's NIC number",
        nicHelp: 'Used to verify their identity against documents submitted later.',
        permissionsTitle: 'What can this nominee do?',
        permissionsSubtitle:
          'Tick only what you want to grant. These become the access this nominee is allowed to use.',
        sensitive: 'Sensitive',
        confirm: 'Save Nominee',
        cancel: 'Cancel',
        processing: 'Saving...',
      },
      removeDialog: {
        title: 'Remove Nominee',
        message: '{{nomineeEmail}} will no longer be able to manage your consents.',
        confirm: 'Remove Nominee',
        cancel: 'Cancel',
        processing: 'Removing...',
      },
    },
    manage: {
      title: "Managing Owner's Consents",
      subtitle:
        'You are acting on behalf of this account. You can only do what the owner authorised you to do.',
      back: 'Exit Nominee View',
      account: {
        title: 'Account access',
        subtitle: 'Actions the owner authorised you to perform on their account.',
        notGranted: 'Not granted by the owner',
      },
      consents: {
        title: 'Consents',
        subtitle: 'View and, where permitted, revoke consents granted by this account.',
      },
      selectedCount: '{{count}} selected',
      revokeSelected: 'Revoke Selected',
      messages: {
        loadFailed: 'Unable to load consents right now.',
        empty: 'No consents found for this account.',
      },
      table: {
        ariaLabel: 'Nominee-managed consent table',
        purposes: 'Purposes',
        type: 'Type',
        status: 'Status',
        updated: 'Updated',
        actions: 'Actions',
        revoke: 'Revoke',
        notRevokable: 'Only active consents can be revoked',
        clientLabel: 'Organization: {{client}}',
      },
      bulkRevoke: {
        title: 'Confirm Bulk Revocation',
        message: 'This will revoke {{count}} consent(s). This cannot be undone.',
        note: 'Each revocation is recorded separately as an action you performed on behalf of the owner.',
        progress: 'Revoking {{processed}} of {{count}}...',
        confirm: 'Revoke Selected',
        cancel: 'Cancel',
        processing: 'Processing...',
      },
    },
    detail: {
      title: 'Consent Details',
      back: 'Back',
    },
  },
  admin: {
    title: 'Nominee Activation',
    subtitle:
      'Search for an account by name or email to activate or deactivate nominee access after manual legal verification.',
    pending: {
      title: 'Awaiting Activation',
      subtitle: 'Nominees who have accepted and are waiting on legal verification.',
      empty: 'Nothing waiting on activation right now.',
    },
    search: {
      label: 'Search by name or email',
      empty: 'No matching accounts found.',
    },
    controls: {
      title: 'Nominee Controls',
      owner: 'Account',
      nominee: 'Nominated to manage this account',
      noNominee: 'No nominee has been set for this account.',
      activatedMeta: 'Activated by {{by}} · Ticket: {{ticket}}',
      activate: 'Activate Nominee Access',
      deactivate: 'Deactivate',
    },
    activateDialog: {
      title: 'Activate Nominee Access',
      subtitle: 'This grants {{nomineeName}} access to manage consents for {{ownerName}}.',
      ticketLabel: 'Legal/support ticket reference',
      confirm: 'Activate Access',
      cancel: 'Cancel',
      processing: 'Activating...',
    },
    deactivateDialog: {
      title: 'Deactivate Nominee Access',
      subtitle: "This immediately revokes the nominee's access to {{ownerName}}'s consents.",
      reasonLabel: 'Reason',
      confirm: 'Deactivate Access',
      cancel: 'Cancel',
      processing: 'Deactivating...',
    },
  },
  auth: {
    signIn: {
      title: 'Sign In',
      redirecting: 'Redirecting to sign in…',
    },
    signUp: {
      title: 'Sign Up',
      redirecting: 'Redirecting to sign up…',
      unavailable: 'Sign-up is not available yet. Contact an administrator.',
    },
  },
} as const

export default commonEn
