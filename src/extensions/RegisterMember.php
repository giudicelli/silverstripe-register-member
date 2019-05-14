<?php

namespace SilverStripe\Security\MemberAuthenticator;

use SilverStripe\ORM\DataExtension;

class RegisterMember extends DataExtension 
{
    private static $db = [
        'RegisterValidated' => 'Boolean',
        'RegisterDate' => 'DBDatetime'
    ];
    
    /**
     * Veto login if user is not confirmed
     */
    function canLogIn() {
        return $this->owner->RegisterValidated;
    }

    /**
     * Veto lost password if user is not confirmed
     */
    function forgotPassword() {
        return $this->owner->RegisterValidated;
    }

}
