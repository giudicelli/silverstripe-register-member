<?php

namespace SilverStripe\Security\MemberAuthenticator;

use SilverStripe\Control\Controller;
use SilverStripe\Control\Email\Email;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\RequestHandler;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\IdentityStore;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;

/**
 * Handle register requests from MemberRegisterForm
 */
class RegisterHandler extends RequestHandler
{
    /**
     * @var Authenticator
     */
    protected $authenticator;

    /**
     * @var array
     */
    private static $url_handlers = [
        '' => 'register',
    ];

    /**
     * @var array
     * @config
     */
    private static $allowed_actions = [
        'register',
        'confirm',
        'RegisterForm'
    ];

    /**
     * Link to this handler
     *
     * @var string
     */
    protected $link = null;

    /**
     * @param string $link The URL to recreate this request handler
     * @param RegisterAuthenticator $authenticator The authenticator to use
     */
    public function __construct($link, RegisterAuthenticator $authenticator)
    {
        $this->link = $link;
        $this->authenticator = $authenticator;
        parent::__construct();
    }

    /**
     * Return a link to this request handler.
     * The link returned is supplied in the constructor
     *
     * @param null|string $action
     * @return string
     */
    public function Link($action = null)
    {
        $link = Controller::join_links($this->link, $action);
        $this->extend('updateLink', $link, $action);
        return $link;
    }

    /**
     * URL handler for the register screen
     *
     * @return array
     */
    public function register()
    {
        return [
            'Form' => $this->RegisterForm(),
        ];
    }

    /**
     * URL handler for the confirmation screen
     *
     * @return array
     */
    public function confirm()
    {
        $request = $this->getRequest();

        $token = $request->getVar('t');
        if(!$token) {
            return $this->redirect($this->Link());
        }
        
        $id = (int)$request->getVar('m');
        if(!$id) {
            return $this->redirect($this->Link());
        }

        // Extract the member from the URL.
        /** @var Member $member */
        $member = Member::get()->filter(['ID' => $id])->first();
        if(!$member) {
            return $this->redirect($this->Link());
        }

        // Check whether we are merely changing password, or resetting.
        if (!$member->validateAutoLoginToken($token)) {
            return $this->redirect($this->Link());
        }
        $member->RegisterValidated = true;
        $member->registerSuccessfulLogin();
        $member->write();

        // Perform login
        $identityStore = Injector::inst()->get(IdentityStore::class);
        $identityStore->logIn($member, false, $request);
        
        return $this->redirectAfterSuccessfulRegister();
    }

    /**
     * Return the MemberRegisterForm form
     *
     * @skipUpgrade
     * @return MemberRegisterForm
     */
    public function RegisterForm()
    {
        return MemberRegisterForm::create(
            $this,
            get_class($this->authenticator),
            'RegisterForm'
        );
    }

    /**
     * Register form handler method
     *
     * This method is called when the user finishes the register flow
     *
     * @param array $data Submitted data
     * @param MemberRegisterForm $form
     * @param HTTPRequest $request
     * @return HTTPResponse
     */
    public function doRegister($data, MemberRegisterForm $form, HTTPRequest $request)
    {
        $failureMessage = null;

        $this->extend('beforeRegister');

        // Check user doesn't exist yet, and create it if possible
        /** @var ValidationResult $result */
        if (($member = $this->checkRegister($data, $request, $result)) ||
            ($member = $this->performRegister($data, $request, $result))) {
            // Allow operations on the member after successful register
            $this->extend('afterRegister', $member);
            
            $form->sessionMessage(_t(__CLASS__.'.MESSAGESENTEMAIL', 'We sent you a confirmation link, you will need to click on it to validate your account'), 'success');

            // Send email to the user
            if(!$member->RegisterValidated) {
                $token = $member->generateAutologinTokenAndStoreHash();
                $this->sendEmail($member, $token);
            }

            return $form->getRequestHandler()->redirectBackToForm();
        }

        $this->extend('failedRegister');
        $message = implode("; ", array_map(
            function ($message) {
                return $message['message'];
            },
            $result->getMessages()
        ));

        $form->sessionMessage($message, 'bad');
        // Fail to register redirects back to form
        return $form->getRequestHandler()->redirectBackToForm();
    }

    public function getReturnReferer()
    {
        return $this->Link();
    }

    /**
     * Register in the user and figure out where to redirect the browser.
     *
     * The $data has this format
     * array(
     *   'AuthenticationMethod' => 'RegisterAuthenticator',
     *   'Email' => 'sam@silverstripe.com',
     *   'Password' => '1nitialPassword',
     *   'BackURL' => 'test/link',
     *   [Optional: 'Remember' => 1 ]
     * )
     *
     * @return HTTPResponse
     */
    protected function redirectAfterSuccessfulRegister()
    {
        $this
            ->getRequest()
            ->getSession()
            ->clear('SessionForms.MemberRegisterForm.Email')
            ->clear('SessionForms.MemberRegisterForm.Remember');

        $member = Security::getCurrentUser();
        if ($member->isPasswordExpired()) {
            return $this->redirectToChangePassword();
        }

        // Absolute redirection URLs may cause spoofing
        $backURL = $this->getBackURL();
        if ($backURL) {
            return $this->redirect($backURL);
        }

        // If a default register dest has been set, redirect to that.
        $defaultRegisterDest = Security::config()->get('default_register_dest');
        if ($defaultRegisterDest) {
            return $this->redirect($defaultRegisterDest);
        }

        // Redirect the user to the page where they came from
        if ($member) {
            // Welcome message
            $message = _t(
                'SilverStripe\\Security\\Member.WELCOMEBACK',
                'Welcome Back, {firstname}',
                ['firstname' => $member->FirstName]
            );
            Security::singleton()->setSessionMessage($message, ValidationResult::TYPE_GOOD);
        }

        // Redirect back
        return $this->redirectBack();
    }

    /**
     * Try to fetch a previously created user
     *
     * @param array $data Submitted data
     * @param HTTPRequest $request
     * @param ValidationResult $result
     * @return Member Returns the member object on successful authentication
     *                or NULL on failure.
     */
    public function checkRegister($data, HTTPRequest $request, ValidationResult &$result = null)
    {
        $member = $this->authenticator->register($data, $request, $result);
        if(!$member || !($member instanceof Member)) {
            return null;
        }
        return $member;
    }

    /**
     * Try to register the user
     *
     * @param Member $member
     * @param array $data Submitted data
     * @param HTTPRequest $request
     * @return Member Returns the member object on successful authentication
     *                or NULL on failure.
     */
    public function performRegister($data, HTTPRequest $request, ValidationResult &$result)
    {
        // Create the member
        $member = Member::create();
        $member->{Member::config()->get('unique_identifier_field')} = $data['Email'];
        $member->FirstName = $data['FirstName'];
        $member->Surname = $data['Surname'];
        $member->Password = $data['Password']['_Password'];
        $member->RegisterValidated = false;
        $member->RegisterDate = date('Y-m-d H:i:s');
        $member->write();
        return $member;
    }

    /**
     * Send the email to the member that registered
     * @param Member $member
     * @param string $token
     * @return bool
     */
    protected function sendEmail($member, $token)
    {
        $token = urldecode($token);
        $link = $this->Link('confirm') . "?m={$member->ID}&t=$token";
    
        /** @var Email $email */
        $email = Email::create()
            ->setHTMLTemplate('SilverStripe\\Control\\Email\\RegisterEmail')
            ->setData($member)
            ->setSubject(_t(
                'SilverStripe\\Security\\Member.SUBJECTREGISTER',
                "Your confirmation link",
                'Email subject'
            ))
            ->addData('RegisterLink', $link)
            ->setTo($member->Email);
        return $email->send();
    }

}
