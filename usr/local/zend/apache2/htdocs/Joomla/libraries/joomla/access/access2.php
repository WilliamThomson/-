	/**
	 * Method to check if a group is authorised to perform an action, optionally on an asset.
	 *
	 * @param   integer         $groupId   The path to the group for which to check authorisation.
	 * @param   string          $action    The name of the action to authorise.
	 * @param   integer|string  $assetKey  The asset key (asset id or asset name). null fallback to root asset.
	 * @param   boolean         $preload   Indicates whether preloading should be used.
	 *
	 * @return  boolean  True if authorised.
	 *
	 * @since   11.1
	 */
	public static function checkGroup($groupId, $action, $assetKey = null, $preload = true)
	{
		// Sanitize input.
		$groupId = (int) $groupId;
		$action  = strtolower(preg_replace('#[\s\-]+#', '.', trim($action)));

		return self::getAssetRules($assetKey, true, true, $preload)->allow($action, self::getGroupPath($groupId));
	}
  
  /**
	 * Method to return the JAccessRules object for an asset.  The returned object can optionally hold
	 * only the rules explicitly set for the asset or the summation of all inherited rules from
	 * parent assets and explicit rules.
	 *
	 * @param   integer|string  $assetKey              The asset key (asset id or asset name). null fallback to root asset.
	 * @param   boolean         $recursive             True to return the rules object with inherited rules.
	 * @param   boolean         $recursiveParentAsset  True to calculate the rule also based on inherited component/extension rules.
	 * @param   boolean         $preload               Indicates whether preloading should be used.
	 *
	 * @return  JAccessRules  JAccessRules object for the asset.
	 *
	 * @since   11.1
	 * @note    The non preloading code will be removed in 4.0. All asset rules should use asset preloading.
	 */
	public static function getAssetRules($assetKey, $recursive = false, $recursiveParentAsset = true, $preload = true)
	{
		// Auto preloads the components assets and root asset (if chosen).
		if ($preload)
		{
			self::preload('components');
		}

		// When asset key is null fallback to root asset.
		$assetKey = self::cleanAssetKey($assetKey);

		// Auto preloads assets for the asset type (if chosen).
		if ($preload)
		{
			self::preload(self::getAssetType($assetKey));
		}

		// Get the asset id and name.
		$assetId = self::getAssetId($assetKey);

		// If asset rules already cached em memory return it (only in full recursive mode).
		if ($recursive && $recursiveParentAsset && $assetId && isset(self::$assetRules[$assetId]))
		{
			return self::$assetRules[$assetId];
		}

		// Get the asset name and the extension name.
		$assetName     = self::getAssetName($assetKey);
		$extensionName = self::getExtensionNameFromAsset($assetName);

		// If asset id does not exist fallback to extension asset, then root asset.
		if (!$assetId)
		{
			if ($extensionName && $assetName !== $extensionName)
			{
				JLog::add('No asset found for ' . $assetName . ', falling back to ' . $extensionName, JLog::WARNING, 'assets');

				return self::getAssetRules($extensionName, $recursive, $recursiveParentAsset, $preload);
			}

			if (self::$rootAssetId !== null && $assetName !== self::$preloadedAssets[self::$rootAssetId])
			{
				JLog::add('No asset found for ' . $assetName . ', falling back to ' . self::$preloadedAssets[self::$rootAssetId], JLog::WARNING, 'assets');

				return self::getAssetRules(self::$preloadedAssets[self::$rootAssetId], $recursive, $recursiveParentAsset, $preload);
			}
		}

		// Almost all calls can take advantage of preloading.
		if ($assetId && isset(self::$preloadedAssets[$assetId]))
		{
			!JDEBUG ?: JProfiler::getInstance('Application')->mark('Before JAccess::getAssetRules (id:' . $assetId . ' name:' . $assetName . ')');

			// Collects permissions for each asset
			$collected = array();

			// If not in any recursive mode. We only want the asset rules.
			if (!$recursive && !$recursiveParentAsset)
			{
				$collected = array(self::$assetPermissionsParentIdMapping[$extensionName][$assetId]->rules);
			}
			// If there is any type of recursive mode.
			else
			{
				$ancestors = array_reverse(self::getAssetAncestors($extensionName, $assetId));

				foreach ($ancestors as $id)
				{
					// If full recursive mode, but not recursive parent mode, do not add the extension asset rules.
					if ($recursive && !$recursiveParentAsset && self::$assetPermissionsParentIdMapping[$extensionName][$id]->name === $extensionName)
					{
						continue;
					}

					// If not full recursive mode, but recursive parent mode, do not add other recursion rules.
					if (!$recursive && $recursiveParentAsset && self::$assetPermissionsParentIdMapping[$extensionName][$id]->name !== $extensionName
						&& self::$assetPermissionsParentIdMapping[$extensionName][$id]->id !== $assetId)
					{
						continue;
					}

					// If empty asset to not add to rules.
					if (self::$assetPermissionsParentIdMapping[$extensionName][$id]->rules === '{}')
					{
						continue;
					}

					$collected[] = self::$assetPermissionsParentIdMapping[$extensionName][$id]->rules;
				}
			}

			/**
			* Hashing the collected rules allows us to store
			* only one instance of the JAccessRules object for
			* Assets that have the same exact permissions...
			* it's a great way to save some memory.
			*/
			$hash = md5(implode(',', $collected));

			if (!isset(self::$assetRulesIdentities[$hash]))
			{
				$rules = new JAccessRules;
				$rules->mergeCollection($collected);

				self::$assetRulesIdentities[$hash] = $rules;
			}

			// Save asset rules to memory cache(only in full recursive mode).
			if ($recursive && $recursiveParentAsset)
			{
				self::$assetRules[$assetId] = self::$assetRulesIdentities[$hash];
			}

			!JDEBUG ?: JProfiler::getInstance('Application')->mark('After JAccess::getAssetRules (id:' . $assetId . ' name:' . $assetName . ')');

			return self::$assetRulesIdentities[$hash];
		}

		// Non preloading code. Use old slower method, slower. Only used in rare cases (if any) or without preloading chosen.
		JLog::add('Asset ' . $assetKey . ' permissions fetch without preloading (slower method).', JLog::INFO, 'assets');

		!JDEBUG ?: JProfiler::getInstance('Application')->mark('Before JAccess::getAssetRules (assetKey:' . $assetKey . ')');

		// There's no need to process it with the recursive method for the Root Asset ID.
		if ((int) $assetKey === 1)
		{
			$recursive = false;
		}

		// Get the database connection object.
		$db = JFactory::getDbo();

		// Build the database query to get the rules for the asset.
		$query = $db->getQuery(true)
			->select($db->qn(($recursive ? 'b.rules' : 'a.rules'), 'rules'))
			->select($db->qn(($recursive ? array('b.id', 'b.name', 'b.parent_id') : array('a.id', 'a.name', 'a.parent_id'))))
			->from($db->qn('#__assets', 'a'));

		// If the asset identifier is numeric assume it is a primary key, else lookup by name.
		$assetString     = is_numeric($assetKey) ? $db->qn('a.id') . ' = ' . $assetKey : $db->qn('a.name') . ' = ' . $db->q($assetKey);
		$extensionString = '';

		if ($recursiveParentAsset && ($extensionName !== $assetKey || is_numeric($assetKey)))
		{
			$extensionString = ' OR ' . $db->qn('a.name') . ' = ' . $db->q($extensionName);
		}

		$recursiveString = $recursive ? ' OR ' . $db->qn('a.parent_id') . ' = 0' : '';

		$query->where('(' . $assetString . $extensionString . $recursiveString . ')');

		// If we want the rules cascading up to the global asset node we need a self-join.
		if ($recursive)
		{
			$query->join('LEFT', $db->qn('#__assets', 'b') . ' ON b.lft <= a.lft AND b.rgt >= a.rgt')
				->order($db->qn('b.lft'));
		}

		// Execute the query and load the rules from the result.
		$result = $db->setQuery($query)->loadObjectList();

		// Get the root even if the asset is not found and in recursive mode
		if (empty($result))
		{
			$assets = JTable::getInstance('Asset', 'JTable', array('dbo' => $db));

			$query->clear()
				->select($db->qn(array('id', 'name', 'parent_id', 'rules')))
				->from($db->qn('#__assets'))
				->where($db->qn('id') . ' = ' . $db->q($assets->getRootId()));

			$result = $db->setQuery($query)->loadObjectList();
		}

		$collected = array();

		foreach ($result as $asset)
		{
			$collected[] = $asset->rules;
		}

		// Instantiate and return the JAccessRules object for the asset rules.
		$rules = new JAccessRules;
		$rules->mergeCollection($collected);

		!JDEBUG ?: JProfiler::getInstance('Application')->mark('Before JAccess::getAssetRules <strong>Slower</strong> (assetKey:' . $assetKey . ')');

		return $rules;
	}
  
  /**
	 * Gets the parent groups that a leaf group belongs to in its branch back to the root of the tree
	 * (including the leaf group id).
	 *
	 * @param   mixed  $groupId  An integer or array of integers representing the identities to check.
	 *
	 * @return  mixed  True if allowed, false for an explicit deny, null for an implicit deny.
	 *
	 * @since   11.1
	 */
	protected static function getGroupPath($groupId)
	{
		// Load all the groups to improve performance on intensive groups checks
		$groups = JHelperUsergroups::getInstance()->getAll();

		if (!isset($groups[$groupId]))
		{
			return array();
		}

		return $groups[$groupId]->path;
	}
