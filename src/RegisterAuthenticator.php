<?php

namespace SilverStripe\Security\MemberAuthenticator;

use InvalidArgumentException;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Extensible;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\DefaultAdminService;
use SilverStripe\Security\LoginAttempt;
use SilverStripe\Security\Member;
use SilverStripe\Security\PasswordEncryptor;
use SilverStripe\Security\Security;

/**
 * Authenticator for the default "member" method
 *
 * @author Sam Minnee <sam@silverstripe.com>
 * @author Simon Erkelens <simonerkelens@silverstripe.com>
 */
class RegisterAuthenticator extends MemberAuthenticator
{
    use Extensible;

    public function supportedServices()
    {
        // Bitwise-OR of all the supported services in this Authenticator, to make a bitmask
        return Authenticator::LOGIN;
    }

    public function register(array $data, HTTPRequest $request, ValidationResult &$result = null)
    {
        // Register a member
        return $this->registerMember($data, $result);
    }

    /**
     * Attempt to register a member if possible from the given data
     *
     * @skipUpgrade
     * @param array $data Form submitted data
     * @param ValidationResult $result
     * @param Member $member This third parameter is used in the CMSAuthenticator(s)
     * @return Member Found member, regardless of successful register
     */
    protected function registerMember($data, ValidationResult &$result = null, Member $member = null)
    {
        $email = !empty($data['Email']) ? $data['Email'] : null;
        $result = $result ?: ValidationResult::create();

        // Attempt to find the user by email
        if (!$email)
            return null;
        
        // Find user by email
        $identifierField = Member::config()->get('unique_identifier_field');
        /** @var Member $member */
        $member = Member::get()
            ->filter([$identifierField => $email])
            ->first();
        return $member;
    }

    /**
     * @param string $link
     * @return RegisterHandler
     */
    public function getLoginHandler($link)
    {
        return RegisterHandler::create($link, $this);
    }
}
