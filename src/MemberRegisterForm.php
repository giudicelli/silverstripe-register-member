<?php

namespace SilverStripe\Security\MemberAuthenticator;

use SilverStripe\Control\Director;
use SilverStripe\Control\RequestHandler;
use SilverStripe\Forms\CheckboxField;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\FormAction;
use SilverStripe\Forms\HiddenField;
use SilverStripe\Forms\LiteralField;
use SilverStripe\Forms\ConfirmedPasswordField;
use SilverStripe\Forms\RequiredFields;
use SilverStripe\Forms\TextField;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\LoginForm as BaseLoginForm;
use SilverStripe\Security\Member;
use SilverStripe\Security\RememberLoginHash;
use SilverStripe\Security\Security;
use SilverStripe\View\Requirements;

/**
 * Log-in form for the "member" authentication method.
 *
 * Available extension points:
 * - "authenticationFailed": Called when register was not successful.
 *    Arguments: $data containing the form submission
 * - "forgotPassword": Called before forgot password logic kicks in,
 *    allowing extensions to "veto" execution by returning FALSE.
 *    Arguments: $member containing the detected Member record
 */
class MemberRegisterForm extends MemberLoginForm
{
    /**
     * Required fields for validation
     *
     * @config
     * @var array
     */
    private static $required_fields = [
        'FirstName',
        'Surname',
        'Email',
        'Password',
    ];

    /**
     * Constructor
     *
     * @skipUpgrade
     * @param RequestHandler $controller The parent controller, necessary to
     *                               create the appropriate form action tag.
     * @param string $authenticatorClass Authenticator for this RegisterForm
     * @param string $name The method on the controller that will return this
     *                     form object.
     * @param FieldList $fields All of the fields in the form - a
     *                                   {@link FieldList} of {@link FormField}
     *                                   objects.
     * @param FieldList|FormAction $actions All of the action buttons in the
     *                                     form - a {@link FieldList} of
     *                                     {@link FormAction} objects
     * @param bool $checkCurrentUser If set to TRUE, it will be checked if a
     *                               the user is currently logged in, and if
     *                               so, only a logout button will be rendered
     */
    public function __construct(
        $controller,
        $authenticatorClass,
        $name,
        $fields = null,
        $actions = null,
        $checkCurrentUser = true
    ) {

        parent::__construct($controller, $authenticatorClass,
                            $name, $fields, $actions,
                            $checkCurrentUser);

        $customCSS = project() . '/css/member_register.css';
        if (Director::fileExists($customCSS)) {
            Requirements::css($customCSS);
        }
    }

    /**
     * Build the FieldList for the register form
     *
     * @skipUpgrade
     * @return FieldList
     */
    protected function getFormFields()
    {
        $request = $this->getRequest();
        if ($request->getVar('BackURL')) {
            $backURL = $request->getVar('BackURL');
        } else {
            $backURL = $request->getSession()->get('BackURL');
        }

        $label = Member::singleton()->fieldLabel(Member::config()->get('unique_identifier_field'));
        $fields = FieldList::create(
            HiddenField::create("AuthenticationMethod", null, $this->authenticator_class, $this),
            // Regardless of what the unique identifer field is (usually 'Email'), it will be held in the
            // 'Email' value, below:
            // @todo Rename the field to a more generic covering name
            $emailField = TextField::create("Email", $label, null, null, $this),
            $firstnameField = TextField::create("FirstName", _t('SilverStripe\\Security\\Member.FIRSTNAME', 'FirstName'), null, null, $this),
            $surnameField = TextField::create("Surname", _t('SilverStripe\\Security\\Member.SURNAME', 'Surname'), null, null, $this),
            $passwordField = ConfirmedPasswordField::create("Password", _t('SilverStripe\\Security\\Member.PASSWORD', 'Password'))
        );
        $emailField->setAttribute('autofocus', 'true');

        // Some browsers won't respect this attribute unless it's added to the form
        $this->setAttribute('autocomplete', 'off');
        $emailField->setAttribute('autocomplete', 'off');
        $surnameField->setAttribute('autocomplete', 'off');
        $firstnameField->setAttribute('autocomplete', 'off');
        $passwordField->minLength = 6;

        if (isset($backURL)) {
            $fields->push(HiddenField::create('BackURL', 'BackURL', $backURL));
        }

        return $fields;
    }

    /**
     * Build default register form action FieldList
     *
     * @return FieldList
     */
    protected function getFormActions()
    {
        $actions = FieldList::create(
            FormAction::create('doRegister', _t('SilverStripe\\Security\\Member.REGISTER', "Register"))
        );
        return $actions;
    }

    /**
     * The name of this register form, to display in the frontend
     * Replaces Authenticator::get_name()
     *
     * @return string
     */
    public function getAuthenticatorName()
    {
        return _t(self::class . '.AUTHENTICATORNAME', "Register");
    }
}
