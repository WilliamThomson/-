	/**
	 * Checks that an action can be performed by an identity.
	 *
	 * The identity is an integer where +ve represents a user group,
	 * and -ve represents a user.
	 *
	 * @param   string  $action    The name of the action.
	 * @param   mixed   $identity  An integer representing the identity, or an array of identities
	 *
	 * @return  mixed   Object or null if there is no information about the action.
	 *
	 * @since   11.1
	 */
	public function allow($action, $identity)
	{
		// Check we have information about this action.
		if (isset($this->data[$action]))
		{
			return $this->data[$action]->allow($identity);
		}

		return;
	}
