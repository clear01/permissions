<?php

declare(strict_types=1);

namespace Damejidlo\ACL;

use Closure;
use Nette\Security\IResource;
use Nette\Security\IRole;

interface IAuthorizator
{
	/**
	 * @param IUser $user
	 * @param IResource|string $resource
	 * @param string $privilege
	 * @return bool
	 */
	public function isAllowed(IUser $user, $resource, $privilege);

	/**
	 * @param IRole[]|string[]|IRole|string $roles
	 * @param string[]|string $resources
	 * @param string[]|string $privileges
	 * @param Closure|NULL $assertion
	 * @return void
	 */
	public function allow($roles, $resources, $privileges, ?Closure $assertion = NULL);

	/**
	 * @param IRole[]|string[]|IRole|string $roles
	 * @param string[]|string $resources
	 * @param string[]|string $privileges
	 * @param Closure|NULL $assertion
	 * @return void
	 */
	public function deny($roles, $resources, $privileges, ?Closure $assertion = NULL);
}
