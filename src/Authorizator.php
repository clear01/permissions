<?php

declare(strict_types=1);

namespace Damejidlo\ACL;

use Closure;
use Nette\Security\IResource;
use Nette\Security\IRole;
use Nette\SmartObject;

class Authorizator implements IAuthorizator
{
	use SmartObject;

	/**
	 * @var Directive[]
	 */
	protected array $directives = [];
	/**
	 * @var string[]
	 */
	protected array $roles = [];
	/**
	 * @var string[]
	 */
	protected array $resources = [];

	/**
	 * @inheritdoc
	 */
	public function isAllowed(IUser $user, $resource, $privilege)
	{
		/**
		 * Go: http://www.wolframalpha.com/
		 * Enter expression: (!C && M && T) || (C && !M && !T) || (C && !M && T) || (C && M && T)
		 * Normalized form: (C && !M) || (M && T)
		 *
		 * Legend:
		 *    C ... means Carry Bit (1 -> you are allowed at this iteration, 0 -> you are denied)
		 *    M ... means Match (1 -> you matched and positively evaluated directive, 0 -> you do not)
		 *    T ... means Type (1 -> Allow Directive, 0 -> Deny Directive)
		 */

		$carry = FALSE;

		foreach ($this->directives as $directive) {
			$match = $directive->evaluate($user, $resource, $privilege);
			$type = $directive->getDirectiveType() === Directive::ALLOW;

			$carry = ($carry && !$match) || ($match && $type);
		}

		return $carry;
	}

	/**
	 * @inheritdoc
	 */
	public function allow($roles, $resources, $privileges, ?Closure $assertion = NULL)
	{
		$this->createDirective(Directive::ALLOW, $roles, $resources, $privileges, $assertion);
	}

	/**
	 * @inheritdoc
	 */
	public function deny($roles, $resources, $privileges, ?Closure $assertion = NULL)
	{
		$this->createDirective(Directive::DENY, $roles, $resources, $privileges, $assertion);
	}

	/**
	 * @param IRole|string $role
	 * @param IRole[]|string[] $parentRoles
	 */
	public function addRole($role, array $parentRoles = [])
	{
		$this->roles[Stringify::stringifyRole($role)] = array_map(function ($role) {
			return Stringify::stringifyRole($role);
		}, $parentRoles);
	}

	/**
	 * @param IResource|string $resource
	 */
	public function addResource($resource)
	{
		$resourceId = Stringify::stringifyResource($resource);
		$this->resources[$resourceId] = $resourceId;
	}

	/**
	 * @param string $directiveType
	 * @param IRole[]|string[]|IRole|string $roles
	 * @param string[]|string $resources
	 * @param string[]|string $privileges
	 * @param Closure|NULL $assertion
	 */
	protected function createDirective($directiveType, $roles, $resources, $privileges, ?Closure $assertion = NULL)
	{
		$roles = is_array($roles) ? $roles : [$roles];
		$resources = is_array($resources) ? $resources : [$resources];
		$privileges = is_array($privileges) ? $privileges : [$privileges];

		$this->validate($roles, $resources);

		$this->directives[] = new Directive($directiveType, $roles, $resources, $privileges, $assertion);
	}

	/**
	 * @param IRole[]|string[] $roles
	 * @param string[] $resources
	 */
	protected function validate(array $roles, array $resources)
	{
		$this->validateRoles($roles);
		$this->validateResources($resources);
	}

	/**
	 * @param IRole[]|string[] $roles
	 */
	protected function validateRoles(array $roles)
	{
		foreach ($roles as $role) {
			$role = Stringify::stringifyRole($role);
			if (!array_key_exists($role, $this->roles)) {
				throw new RoleDoesNotExists("Role '{$role}' does not exists.");
			}
		}
	}

	/**
	 * @param string[] $resources
	 */
	protected function validateResources(array $resources)
	{
		foreach ($resources as $resource) {
			$resource = Stringify::stringifyResource($resource);
			if (!array_key_exists($resource, $this->resources)) {
				throw new ResourceDoesNotExists("Resource '{$resource}' does not exists.");
			}
		}
	}
}
