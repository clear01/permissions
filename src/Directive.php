<?php

declare(strict_types=1);

namespace Damejidlo\ACL;

use Closure;
use Nette\Security\IResource;
use Nette\Security\IRole;
use Nette\SmartObject;
use function bdump;

class Directive
{
	use SmartObject;

	public const ALLOW = 'allow';
	public const DENY = 'deny';
	/**
	 * @var IRole[]string[]
	 */
	private array $roles = [];
	/**
	 * @var string[]
	 */
	private array $resources = [];
	/**
	 * @var string[]
	 */
	private array $privileges = [];
	/**
	 * @var Closure|NULL
	 */
	private $assertion;
	/**
	 * @var string
	 */
	private $directiveType;

	/**
	 * @param string $directiveType
	 * @param IRole[]|string[]|IRole|string $roles
	 * @param string[] $resources
	 * @param string[] $privileges
	 * @param Closure|NULL $assertion
	 */
	public function __construct(
		$directiveType,
		array $roles,
		array $resources,
		array $privileges,
		?Closure $assertion = NULL
	)
	{
		$this->roles = $roles;
		$this->resources = $resources;
		$this->privileges = $privileges;
		$this->assertion = $assertion;
		$this->directiveType = $directiveType;
	}

	/**
	 * @param IUser $user
	 * @param IResource|string $resource
	 * @param string $privilege
	 * @return bool
	 */
	public function evaluate(IUser $user, $resource, $privilege)
	{
		foreach ($this->roles as $role) {
			foreach ($user->getRoles() as $usersRole) {
				$roleId = Stringify::stringifyRole($role);
				$usersRoleId = Stringify::stringifyRole($usersRole);
				bdump([$roleId, $usersRoleId]);

				if ($roleId === $usersRoleId) {
					$queried = $this->isResourceQueried($resource) && $this->isPrivilegeQueried($privilege);
					$assertion = $this->assertion;

					return $queried && ($assertion === NULL || $assertion($user, $role, $resource));
				}
			}
		}

		return FALSE;
	}

	/**
	 * @return string
	 */
	public function getDirectiveType()
	{
		return $this->directiveType;
	}

	/**
	 * @param IResource|string $usersResource
	 * @return bool
	 */
	private function isResourceQueried($usersResource)
	{
		$usersResourceId = Stringify::stringifyResource($usersResource);
		foreach ($this->resources as $resource) {
			$resourceId = Stringify::stringifyResource($resource);
			if ($usersResourceId === $resourceId) {
				return TRUE;
			}
		}

		return FALSE;
	}

	/**
	 * @param string $privilege
	 * @return bool
	 */
	private function isPrivilegeQueried($privilege)
	{
		return in_array($privilege, $this->privileges, TRUE);
	}
}
