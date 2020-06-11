# frozen_string_literal: true

require 'omniauth/strategies/oauth2'
require 'uri'

# Potential scopes: https://developer.atlassian.com/cloud/jira/platform/scopes/
# offline_access read:jira-user read:jira-work write:jira-work manage:jira-project manage:jira-configuration
#
# Separate scopes with a space (%20)
# https://developer.atlassian.com/cloud/jira/platform/oauth-2-authorization-code-grants-3lo-for-apps/

module OmniAuth
  module Strategies
    # Omniauth strategy for Atlassian
    class AtlassianOauth2 < OmniAuth::Strategies::OAuth2
      option :name, 'atlassian_oauth2'
      option :client_options,
             site: 'https://auth.atlassian.com',
             authorize_url: 'https://auth.atlassian.com/authorize',
             token_url: 'https://auth.atlassian.com/oauth/token',
             audience: 'api.atlassian.com'
      option :authorize_params,
             prompt: 'consent',
             audience: 'api.atlassian.com'

      uid do
        raw_info['myself']['account_id']
      end

      info do
        {
          name: raw_info['myself']['name'],
          email: raw_info['myself']['email'],
          nickname: raw_info['myself']['nickname'],
          location: raw_info['myself']['extended_profile']['location'],
          job_title: raw_info['myself']['extended_profile']['job_title'],
          image: raw_info['myself']['picture'],
          account_status: raw_info['myself']['account_status'],
          timezone: raw_info['myself']['zoneinfo']
        }
      end

      extra do
        {
          'raw_info' => raw_info
        }
      end

      def raw_info
        return @raw_info if @raw_info

        sites = JSON.parse(access_token.get('https://api.atlassian.com/oauth/token/accessible-resources').body)
        myself = JSON.parse(access_token.get('https://api.atlassian.com/me').body)

        @raw_info ||= {
          'sites' => sites,
          'myself' => myself
        }
      end
    end
  end
end
