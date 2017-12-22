	/**
	 * Load all user groups from the database.
	 *
	 * @return  self
	 *
	 * @since   3.6.3
	 */
	public function loadAll()
	{
		$this->groups = array();

		$db = \JFactory::getDbo();

		$query = $db->getQuery(true)
			->select('*')
			->from('#__usergroups')
			->order('lft ASC');

		$db->setQuery($query);

		$groups = $db->loadObjectList('id');

		$this->groups = $groups ?: array();
		$this->populateGroupsData();

		return $this;
	}
  
  /**
	 * Get the helper instance.
	 *
	 * @return  self
	 *
	 * @since   3.6.3
	 */
	public static function getInstance()
	{
		if (static::$instance === null)
		{
			// Only here to avoid code style issues...
			$groups = array();

			static::$instance = new static($groups, static::MODE_SINGLETON);
		}

		return static::$instance;
	}
