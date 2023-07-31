<?php

/*
 * This file is part of the FOSUserBundle package.
 *
 * (c) FriendsOfSymfony <http://friendsofsymfony.github.com/>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FOS\UserBundle\EventListener;

use FOS\UserBundle\Event\UserEvent;
use FOS\UserBundle\FOSUserEvents;
use FOS\UserBundle\Model\UserInterface;
use FOS\UserBundle\Model\UserManagerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;
use Symfony\Component\Security\Http\SecurityEvents;

class LastLoginListener implements EventSubscriberInterface
{
    protected $userManager;

    /**
     * LastLoginListener constructor.
     *
     * @param UserManagerInterface $userManager
     */
    public function __construct(UserManagerInterface $userManager)
    {
        $this->userManager = $userManager;
    }

    /**
     * @return array
     */
    public static function getSubscribedEvents()
    {
        return array(
            FOSUserEvents::SECURITY_IMPLICIT_LOGIN => 'onImplicitLogin',
            LoginSuccessEvent::class => 'onSecurityInteractiveLogin',
        );
    }

    /**
     * @param UserEvent $event
     */
    public function onImplicitLogin(UserEvent $event)
    {
        $user = $event->getUser();

        $user->setLastLogin(new \DateTime());
        $this->userManager->updateUser($user);
    }

    /**
     * @param LoginSuccessEvent $event
     */
    public function onSecurityInteractiveLogin(LoginSuccessEvent $event)
    {
        $user = $event->getAuthenticatedToken()->getUser();

        if ($user instanceof UserInterface) {
            $user->setLastLogin(new \DateTime());
            $this->userManager->updateUser($user);
        }
    }
}
