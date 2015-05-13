<?php

class AuthCAS extends AuthPluginBase {

    private $userDetails = array();
    protected $storage = 'DbStorage';
    static protected $description = 'CAS authentication plugin';
    static protected $name = 'CAS';
    protected $settings = array(
        'casAuthServer' => array(
            'type' => 'string',
            'label' => 'The servername of the CAS Server without protocol',
            'default' => 'localhost',
        ),
        'casAuthPort' => array(
            'type' => 'int',
            'label' => 'CAS Server listening Port',
            'default' => 443,
        ),
        'casAuthUri' => array(
            'type' => 'string',
            'label' => 'Relative uri from CAS Server to cas workingdirectory',
            'default' => '/cas',
        ),
        'casAttribute' => array(
            'type' => 'string',
            'label' => "A CASAttribute to validate against(if blank don't authenticate)",
            'default' => '',
        ),
        'casLoginFailMessage' => array(
            'type' => 'string',
            'label' => "Error message to be displayed when authentication fails due to casAttribute value",
            'default' => 'Authentication failed.',
        ),
        'autoCreate' => array(
            'type' => 'select',
            'label' => 'Enable automated creation of user from CAS ?',
            'options' => array("0" => "No, don't create user automatically", "1" => "User creation on the first connection"),
            'default' => '0',
            'submitonchange' => false
        ),
    );

    public function __construct(\PluginManager $manager, $id) {
        parent::__construct($manager, $id);

        $this->subscribe('beforeLogin');
        $this->subscribe('newUserSession');
        $this->subscribe('beforeLogout');
    }

    public function beforeLogin() {
        // configure phpCAS
        $cas_host = $this->get('casAuthServer');
        $cas_context = $this->get('casAuthUri');
        $cas_port = (int) $this->get('casAuthPort');

        // import phpCAS lib
        $basedir = dirname(__FILE__);
        Yii::setPathOfAlias('myplugin', $basedir);
        Yii::import('myplugin.third_party.CAS.*');
        require_once('CAS.php');
        // Initialize phpCAS
        phpCAS::client(CAS_VERSION_2_0, $cas_host, $cas_port, $cas_context, false);
        // disable SSL validation of the CAS server
        phpCAS::setNoCasServerValidation();
        //force CAS authentication
        phpCAS::forceAuthentication();

        $this->setUsername(phpCAS::getUser());
        $oUser = $this->api->getUserByName($this->getUserName());


        $casAttr = trim($this->get('casAttribute'));
        $casAttrValue = '';

        if (strlen($casAttr) > 0) {

            if (isset(phpCAS::getAttributes()[$this->get('casAttribute')])) {
                $casAttrValue = trim(phpCAS::getAttributes()[$this->get('casAttribute')]);

                if (strlen($casAttrValue) == 0) {
                    throw new CHttpException(401, $this->get('casLoginFailMessage'));
                } else {
                    $casAttrValue = '-' . $casAttrValue;
                }
            } else {
                throw new CHttpException(401, 'Cas Attribute not found.');
            }
        }

        $this->userDetails['email'] = phpCAS::getAttributes()['mail'];
        $this->userDetails['full_name'] = phpCAS::getUser() . $casAttrValue;
        $this->userDetails['username'] = phpCAS::getUser();


        if ($oUser || $this->get('autoCreate')) {
            // User authenticated and found. Cas become the authentication system
            $this->getEvent()->set('default', get_class($this));
            $this->setAuthPlugin(); // This plugin handles authentication, halt further execution of auth plugins
        } elseif ($this->get('is_default', null, null)) {
            // Fall back to another authentication mecanism
            throw new CHttpException(401, 'Wrong credentials for LimeSurvey administration.');
        }
    }

    public function newUserSession() {
        // Do nothing if this user is not AuthCAS type
        $identity = $this->getEvent()->get('identity');

        if ($identity->plugin != 'AuthCAS') {
            return;
        }

        $sUser = $this->getUserName();

        $oUser = $this->api->getUserByName($sUser);
        if ((boolean) $this->get('autoCreate') === true) {

            if (is_null($oUser)) {

                $oUser = new User;
                $oUser->users_name = $this->userDetails['username'];
                $oUser->password = hash('sha256', createPassword());
                $oUser->full_name = $this->userDetails['full_name'];
                $oUser->parent_id = 1;
                $oUser->email = $this->userDetails['email'];

                if ($oUser->save()) {
                    if ($this->api->getConfigKey('auth_cas_autocreate_permissions')) {
                        $permission = new Permission;
                        $permission->setPermissions($oUser->uid, 0, 'global', $this->api->getConfigKey('auth_cas_autocreate_permissions'), true);
                    }
                    // read again user from newly created entry
                    $this->setAuthSuccess($oUser);
                    return;
                } else {
                    $this->setAuthFailure(self::ERROR_USERNAME_INVALID);
                    throw new CHttpException(401, 'User not saved : ' . $this->userDetails['email'] . " / " . $this->userDetails['full_name']);
                    return;
                }
            } else {

                $isChanged = FALSE;

                if (trim($this->userDetails['full_name']) != trim($oUser->getAttribute('full_name'))) {
                    $oUser->full_name = $this->userDetails[full_name];
                    $isChanged = TRUE;
                }
                //  }

                if (trim($this->userDetails['email']) != trim($oUser->getAttribute('email'))) {
                    $oUser->email = $this->userDetails['email'];
                    $isChanged = TRUE;
                }

                if ($isChanged) {
                    if ($oUser->save()) {
                        $this->setAuthSuccess($oUser);
                        return;
                    } else {
                        $this->setAuthFailure(self::ERROR_USERNAME_INVALID);
                        throw new CHttpException(401, 'User not saved : ' . $this->userDetails['email'] . " / " . $this->userDetails['full_name']);
                        return;
                    }
                } else {
                    $this->setAuthSuccess($oUser);
                    return;
                }
            }
        }
    }

    public function beforeLogout() {
        // configure phpCAS
        $cas_host = $this->get('casAuthServer');
        $cas_context = $this->get('casAuthUri');
        $cas_port = (int) $this->get('casAuthPort');
        // import phpCAS lib
        $basedir = dirname(__FILE__);
        Yii::setPathOfAlias('myplugin', $basedir);
        Yii::import('myplugin.third_party.CAS.*');
        require_once('CAS.php');
        // Initialize phpCAS
        phpCAS::client(CAS_VERSION_2_0, $cas_host, $cas_port, $cas_context, false);
        // disable SSL validation of the CAS server
        phpCAS::setNoCasServerValidation();
        // logout from CAS
        phpCAS::logout();
    }

}
