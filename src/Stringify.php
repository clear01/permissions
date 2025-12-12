<?php

declare(strict_types=1);

namespace Damejidlo\ACL;

use Nette\Security\IResource;
use Nette\Security\IRole;
use Nette\SmartObject;

class Stringify
{
	use SmartObject;

	/**
	 * @param IResource|string $resource
	 * @return string
	 */
	public static function stringifyResource($resource)
	{
		return $resource instanceof IResource ? $resource->getResourceId() : $resource;
	}

	/**
	 * @param IRole|string $role
	 * @return string
	 */
	public static function stringifyRole($role)
	{
		return $role instanceof IRole ? $role->getRoleId() : $role;
	}
}
