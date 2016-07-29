<?php

namespace Akkyoh\SocialiteBitbucket;

use Laravel\Socialite\Two\InvalidStateException;
use Laravel\Socialite\Two\ProviderInterface;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;

class Provider extends AbstractProvider implements ProviderInterface
{
    /**
     * Unique Provider Identifier.
     */
    const IDENTIFIER = 'BITBUCKET';

    /**
     * {@inheritdoc}
     */
    protected $scopes = ['account'];

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        return $this -> buildAuthUrlFromBase(
            'https://bitbucket.org/site/oauth2/authorize', $state
        );
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return 'https://bitbucket.org/site/oauth2/access_token';
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        $account = $this -> getHttpClient() -> get(
            'https://api.bitbucket.org/2.0/user?access_token='.$token['access_token']
        );
        $emails = $this -> getHttpClient() -> get(
            'https://api.bitbucket.org/2.0/user/emails?access_token='.$token['access_token']
        );

        $account = json_decode($account -> getBody() -> getContents(), true);
        $emails = json_decode($emails -> getBody() -> getContents(), true);

        return array_merge($account, ['email' => $emails['values'][0]['email']]);
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        return (new User()) -> setRaw($user) -> map([
            'id' => substr($user['uuid'], 1, strlen($user['uuid'])-2), // use uuid, because username may be change from bitbucket.org interface
            'nickname' => $user['username'],
            'name' => $user['display_name'],
            'email' => $user['email'],
            'avatar' => $user['links']['avatar']['href'],
        ]);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenFields($code)
    {
        return array_merge(parent::getTokenFields($code), [
            'grant_type' => 'authorization_code',
        ]);
    }

    /**
     * {@inheritdoc}
     */
    protected function parseAccessToken($body)
    {
        return json_decode($body, true);
    }

    /**
     * {@inheritdoc}
     */
    public function user()
    {
        if ($this -> hasInvalidState())
            throw new InvalidStateException();

        $user = $this -> mapUserToObject($this -> getUserByToken(
            $token = $this -> getAccessTokenResponse($this -> getCode())
        ));

        return $user->setToken(array_get($token, 'access_token'));
    }
}
