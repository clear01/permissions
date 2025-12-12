<?php

declare(strict_types=1);

namespace Damejidlo\ACL;

use Nette\Security\IRole;



interface IUser
{

	/**
	 * @return mixed
	 */
	public function getEntity();



	/**
	 * @return IRole[]|string[]
	 */
	public function getRoles();

}
