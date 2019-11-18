# frozen_string_literal: true

# name: discourse-openid-connect
# about: Add support for openid-connect as a login provider
# version: 1.0
# authors: David Taylor
# url: https://github.com/discourse/discourse-openid-connect

require_relative "lib/omniauth_open_id_connect"

class OpenIDConnectAuthenticator < Auth::ManagedAuthenticator

  def name
    'oidc'
  end

  def can_revoke?
    SiteSetting.openid_connect_allow_association_change
  end

  def can_connect_existing_user?
    SiteSetting.openid_connect_allow_association_change
  end

  def enabled?
    SiteSetting.openid_connect_enabled
  end
  
  def after_authenticate(auth_token, existing_account: nil)
    Rails.logger.info("after_authenticate called with uuid #{auth_token[:uid]} and email #{auth_token[:info][:email]}")
    
    user = User.find_by_email(auth_token[:info][:email])
    if user
      Rails.logger.info("found user by email #{auth_token[:info][:email]}")
      
      association = UserAssociatedAccount.find_by(provider_name: auth_token[:provider], provider_uid: auth_token[:uid])
      if association
         Rails.logger.info("found associated_account with email #{association.info["email"]} and uuid #{association.provider_uid}")
         
         if auth_token[:info][:email] == association.info["email"]
           Rails.logger.info("associated account fits to email+uuid combination")
           result = super(auth_token, existing_account: existing_account)
         else
           Rails.logger.info("associated email is different to provided user email")
           result = Auth::Result.new
           result.failed = true
           result.failed_reason = "found associated account is not assigned to provided user email"
         end
        
         #user = association&.user
         #Rails.logger.info("found user #{user.inspect}")
      else
         Rails.logger.info("no associated_account found for this uuid")
         result = super(auth_token, existing_account: existing_account)  
         Jobs.enqueue(:critical_user_email, user_id: user.id, type: :suspicious_login)
         Rails.logger.info("info mail send to user")
      end
    else
      Rails.logger.info("no user found for this email. creating new user account with association.")
      result = super(auth_token, existing_account: existing_account)
    end
      
    result
  end

  def register_middleware(omniauth)

    omniauth.provider :openid_connect,
      name: :oidc,
      cache: lambda { |key, &blk| Rails.cache.fetch(key, expires_in: 10.minutes, &blk) },
      error_handler: lambda { |error, message|
        handlers = SiteSetting.openid_connect_error_redirects.split("\n")
        handlers.each do |row|
          parts = row.split("|")
          return parts[1] if message.include? parts[0]
        end
        nil
      },
      verbose_logger: lambda { |message|
        return unless SiteSetting.openid_connect_verbose_logging
        Rails.logger.warn("OIDC Log: #{message}")
      },
      setup: lambda { |env|
        opts = env['omniauth.strategy'].options
        opts.deep_merge!(
          client_id: SiteSetting.openid_connect_client_id,
          client_secret: SiteSetting.openid_connect_client_secret,
          client_options: {
            discovery_document: SiteSetting.openid_connect_discovery_document,
          },
          scope: SiteSetting.openid_connect_authorize_scope,
          token_params: {
            scope: SiteSetting.openid_connect_token_scope,
          }
        )
      }
  end
end

# TODO: remove this check once Discourse 2.2 is released
if Gem.loaded_specs['jwt'].version > Gem::Version.create('2.0')
  auth_provider authenticator: OpenIDConnectAuthenticator.new(),
                full_screen_login: true
else
  STDERR.puts "WARNING: discourse-openid-connect requires Discourse v2.2.0.beta7 or above. The plugin will not be loaded."
end
