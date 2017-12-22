	/**
	 * Method to store the permission values in the asset table.
   * 保存权限值到asset表的方法
	 *
	 * This method will get an array with permission key value pairs and transform it
	 * into json and update the asset table in the database.
   * 获取包含权限值对的数组，然后转换为json数据，再更新数据库中的asset表。
	 *
	 * @param   string  $permission  Need an array with Permissions (component, rule, value and title)
	 *
	 * @return  array  A list of result data.
	 *
	 * @since   3.5
	 */
	public function storePermissions($permission = null)
	{
		$app  = JFactory::getApplication();
		$user = JFactory::getUser();

		if (is_null($permission))
		{
			// Get data from input.
			$permission = array(
				'component' => $app->input->get('comp'),
				'action'    => $app->input->get('action'),
				'rule'      => $app->input->get('rule'),
				'value'     => $app->input->get('value'),
				'title'     => $app->input->get('title', '', 'RAW')
			);
		}

		// We are creating a new item so we don't have an item id so don't allow.
    // 创建新项目由于没有id不被允许
		if (substr($permission['component'], -6) === '.false')
		{
			$app->enqueueMessage(JText::_('JLIB_RULES_SAVE_BEFORE_CHANGE_PERMISSIONS'), 'error');

			return false;
		}

		// Check if the user is authorized to do this.
    // 检查用户是否被授权
		if (!$user->authorise('core.admin', $permission['component']))
		{
			$app->enqueueMessage(JText::_('JERROR_ALERTNOAUTHOR'), 'error');

			return false;
		}

		$permission['component'] = empty($permission['component']) ? 'root.1' : $permission['component'];

		// Current view is global config?
    // 当前视图是否全局配置
		$isGlobalConfig = $permission['component'] === 'root.1';

		// Check if changed group has Super User permissions.
    // 检查是否需要调整的组是否有超级用户权限
		$isSuperUserGroupBefore = JAccess::checkGroup($permission['rule'], 'core.admin');

		// Check if current user belongs to changed group.
    // 检查是否当前用户是否属于要被修改的组
		$currentUserBelongsToGroup = in_array((int) $permission['rule'], $user->groups) ? true : false;

		// Get current user groups tree.
    // 获取当前用户组树
		$currentUserGroupsTree = JAccess::getGroupsByUser($user->id, true);

		// Check if current user belongs to changed group.
    // 检查当前用户是否属于需要调整的组
		$currentUserSuperUser = $user->authorise('core.admin');

		// If user is not Super User cannot change the permissions of a group it belongs to.
    // 如果用户不是超级用户不能调整
		if (!$currentUserSuperUser && $currentUserBelongsToGroup)
		{
			$app->enqueueMessage(JText::_('JLIB_USER_ERROR_CANNOT_CHANGE_OWN_GROUPS'), 'error');

			return false;
		}

		// If user is not Super User cannot change the permissions of a group it belongs to.
    // 如果用户不是超级用户不要改变她所在组的权限
		if (!$currentUserSuperUser && in_array((int) $permission['rule'], $currentUserGroupsTree))
		{
			$app->enqueueMessage(JText::_('JLIB_USER_ERROR_CANNOT_CHANGE_OWN_PARENT_GROUPS'), 'error');

			return false;
		}

		// If user is not Super User cannot change the permissions of a Super User Group.
    // 如果用户不是超级用户不要改变超级用户组的权限
		if (!$currentUserSuperUser && $isSuperUserGroupBefore && !$currentUserBelongsToGroup)
		{
			$app->enqueueMessage(JText::_('JLIB_USER_ERROR_CANNOT_CHANGE_SUPER_USER'), 'error');

			return false;
		}

		// If user is not Super User cannot change the Super User permissions in any group it belongs to.
    // 如果用户不是超级用户不要修改他所在的任何组的超级用户权限
		if ($isSuperUserGroupBefore && $currentUserBelongsToGroup && $permission['action'] === 'core.admin')
		{
			$app->enqueueMessage(JText::_('JLIB_USER_ERROR_CANNOT_DEMOTE_SELF'), 'error');

			return false;
		}

		try
		{
			$asset  = JTable::getInstance('asset');
			$result = $asset->loadByName($permission['component']);

			if ($result === false)
			{
				$data = array($permission['action'] => array($permission['rule'] => $permission['value']));

				$rules        = new JAccessRules($data);
				$asset->rules = (string) $rules;
				$asset->name  = (string) $permission['component'];
				$asset->title = (string) $permission['title'];

				// Get the parent asset id so we have a correct tree.
        // 获取父系asset id 以便我们有正确的树
				$parentAsset = JTable::getInstance('Asset');

				if (strpos($asset->name, '.') !== false)
				{
					$assetParts = explode('.', $asset->name);
					$parentAsset->loadByName($assetParts[0]);
					$parentAssetId = $parentAsset->id;
				}
				else
				{
					$parentAssetId = $parentAsset->getRootId();
				}

				/**
				 * @to do: incorrect ACL stored
				 * When changing a permission of an item that doesn't have a row in the asset table the row a new row is created.
				 * This works fine for item <-> component <-> global config scenario and component <-> global config scenario.
				 * But doesn't work properly for item <-> section(s) <-> component <-> global config scenario,
				 * because a wrong parent asset id (the component) is stored.
				 * Happens when there is no row in the asset table (ex: deleted or not created on update).
				 */
         
        /**
				 * @to do: 不正确的ACL存储
				 * 当改变asset表中没有记录的item权限时，新的纪录被创建
				 * 这有利于item <-> component <-> global和component <-> global配置方案
				 * 却不适于item <-> section(s) <-> component <-> global配置方案
				 * 是因为错误的parent asset id会被存储。
				 * 发生在表中没有记录的情况下
				 */


				$asset->setLocation($parentAssetId, 'last-child');
			}
			else
			{
				// Decode the rule settings.
        //编码规则设置
				$temp = json_decode($asset->rules, true);

				// Check if a new value is to be set.
        // 检查是否新值被设定
				if (isset($permission['value']))
				{
					// Check if we already have an action entry.
          // 检查是否已经有action入口
					if (!isset($temp[$permission['action']]))
					{
						$temp[$permission['action']] = array();
					}

					// Check if we already have a rule entry.
          // 检查是否我们已经有rule入口
					if (!isset($temp[$permission['action']][$permission['rule']]))
					{
						$temp[$permission['action']][$permission['rule']] = array();
					}

					// Set the new permission.
          // 设定心权限
					$temp[$permission['action']][$permission['rule']] = (int) $permission['value'];

					// Check if we have an inherited setting.
          //检查是否我们有继承来的设置
					if ($permission['value'] === '')
					{
						unset($temp[$permission['action']][$permission['rule']]);
					}

					// Check if we have any rules.
          // 检查是否有任何规则
					if (!$temp[$permission['action']])
					{
						unset($temp[$permission['action']]);
					}
				}
				else
				{
					// There is no value so remove the action as it's not needed.
          // 没有值所以移除action因为它不需要。
					unset($temp[$permission['action']]);
				}

				$asset->rules = json_encode($temp, JSON_FORCE_OBJECT);
			}

			if (!$asset->check() || !$asset->store())
			{
				$app->enqueueMessage(JText::_('JLIB_UNKNOWN'), 'error');

				return false;
			}
		}
		catch (Exception $e)
		{
			$app->enqueueMessage($e->getMessage(), 'error');

			return false;
		}


		// All checks done.
    //所有检查完成
		$result = array(
			'text'    => '',
			'class'   => '',
			'result'  => true,
		);

		// Show the current effective calculated permission considering current group, path and cascade.
    // 显示对当前组，路径，流

		try
		{
			// Get the asset id by the name of the component.
      // 获取asset id 通过 componet name
			$query = $this->db->getQuery(true)
				->select($this->db->quoteName('id'))
				->from($this->db->quoteName('#__assets'))
				->where($this->db->quoteName('name') . ' = ' . $this->db->quote($permission['component']));

			$this->db->setQuery($query);

			$assetId = (int) $this->db->loadResult();

			// Fetch the parent asset id.
      // 取出parent id
			$parentAssetId = null;

			/**
			 * @to do: incorrect info
			 * When creating a new item (not saving) it uses the calculated permissions from the component (item <-> component <-> global config).
			 * But if we have a section too (item <-> section(s) <-> component <-> global config) this is not correct.
			 * Also, currently it uses the component permission, but should use the calculated permissions for achild of the component/section.
			 */
       
      /**
			 * @to do: 不正确的信息
			 * 当创建新item (not saving) 将使用从component计算出的权限 (item <-> component <-> global config).
			 * 但是如果我们也有一部分(item <-> section(s) <-> component <-> global config)，这会是错误的
			 * 还有，当前使用的component permission，但不应该使用计算过的权限
			 */
       

			// If not in global config we need the parent_id asset to calculate permissions.
      // 如果不是全局设置我们需要父系设置以计算权限
			if (!$isGlobalConfig)
			{
				// In this case we need to get the component rules too.
        // 这种情况我们可以获取rules
				$query->clear()
					->select($this->db->quoteName('parent_id'))
					->from($this->db->quoteName('#__assets'))
					->where($this->db->quoteName('id') . ' = ' . $assetId);

				$this->db->setQuery($query);

				$parentAssetId = (int) $this->db->loadResult();
			}

			// Get the group parent id of the current group.
      // 获取group parent id
			$query->clear()
				->select($this->db->quoteName('parent_id'))
				->from($this->db->quoteName('#__usergroups'))
				->where($this->db->quoteName('id') . ' = ' . (int) $permission['rule']);

			$this->db->setQuery($query);

			$parentGroupId = (int) $this->db->loadResult();

			// Count the number of child groups of the current group.
      // 数当前组子组的数
			$query->clear()
				->select('COUNT(' . $this->db->quoteName('id') . ')')
				->from($this->db->quoteName('#__usergroups'))
				->where($this->db->quoteName('parent_id') . ' = ' . (int) $permission['rule']);

			$this->db->setQuery($query);

			$totalChildGroups = (int) $this->db->loadResult();
		}
		catch (Exception $e)
		{
			$app->enqueueMessage($e->getMessage(), 'error');

			return false;
		}

		// Clear access statistics.
    // 清除访问统计
		JAccess::clearStatics();

		// After current group permission is changed we need to check again if the group has Super User permissions.
    // 在当前用户组权限被改变后我们需要再检查组是否还有超级用户权限
		$isSuperUserGroupAfter = JAccess::checkGroup($permission['rule'], 'core.admin');

		// Get the rule for just this asset (non-recursive) and get the actual setting for the action for this group.
    // 只获取这个asset的rule, 然后获取实际设定
		$assetRule = JAccess::getAssetRules($assetId, false, false)->allow($permission['action'], $permission['rule']);

		// Get the group, group parent id, and group global config recursive calculated permission for the chosen action.
    //  获取group, group parent id, and group global config
		
		$inheritedGroupRule = JAccess::checkGroup($permission['rule'], $permission['action'], $assetId);

		if (!empty($parentAssetId))
		{
			$inheritedGroupParentAssetRule = JAccess::checkGroup($permission['rule'], $permission['action'], $parentAssetId);
		}
		else
		{
			$inheritedGroupParentAssetRule = null;
		}

		$inheritedParentGroupRule = !empty($parentGroupId) ? JAccess::checkGroup($parentGroupId, $permission['action'], $assetId) : null;

		// Current group is a Super User group, so calculated setting is "Allowed (Super User)".
    // 当前组是超级用户组，因此计算的设定是“Allowed”
		if ($isSuperUserGroupAfter)
		{
			$result['class'] = 'label label-success';
			$result['text'] = '<span class="icon-lock icon-white" aria-hidden="true"></span>' . JText::_('JLIB_RULES_ALLOWED_ADMIN');
		}
		// Not super user.
    // 非超级用户
		else
		{
			// First get the real recursive calculated setting and add (Inherited) to it.
      // 首先获取事实上的递归计算出的设定然后加上他

			// If recursive calculated setting is "Denied" or null. Calculated permission is "Not Allowed (Inherited)".
      // 如果递归计算的设定是“拒绝”或者“空”。 计算出的全权限是“Not Allowed”
			if ($inheritedGroupRule === null || $inheritedGroupRule === false)
			{
				$result['class'] = 'label label-important';
				$result['text']  = JText::_('JLIB_RULES_NOT_ALLOWED_INHERITED');
			}
			// If recursive calculated setting is "Allowed". Calculated permission is "Allowed (Inherited)".
      // 如果递归计算的设定是“允许”。计算权限是“Allowed”
			
      else
			{
				$result['class'] = 'label label-success';
				$result['text']  = JText::_('JLIB_RULES_ALLOWED_INHERITED');
			}

			// Second part: Overwrite the calculated permissions labels if there is an explicity permission in the current group.
      // 第二部分：如果在当前组有明确的权限覆盖计算出的permissions标签

			/**
			 * @to do: incorect info
			 * If a component has a permission that doesn't exists in global config (ex: frontend editing in com_modules) by default
			 * we get "Not Allowed (Inherited)" when we should get "Not Allowed (Default)".
			 */
       
      /**
			 * @to do: incorect info
			 * 如果一个组件有默认全局设置不存在的权限，我们需要获取不允许(Inherited)当我们不允许(Default)
			 * 
			 */

			// If there is an explicity permission "Not Allowed". Calculated permission is "Not Allowed".
      // 如果没有明确的“Not Allowed”
			if ($assetRule === false)
			{
				$result['class'] = 'label label-important';
				$result['text']  = JText::_('JLIB_RULES_NOT_ALLOWED');
			}
			// If there is an explicity permission is "Allowed". Calculated permission is "Allowed".
      // 如果有一个明确的权限是“Allowed”。计算的权限是“Allowed”
			elseif ($assetRule === true)
			{
				$result['class'] = 'label label-success';
				$result['text']  = JText::_('JLIB_RULES_ALLOWED');
			}

			// Third part: Overwrite the calculated permissions labels for special cases.
      // 第三部分：对于特殊情况下覆盖计算出的权限

			// Global configuration with "Not Set" permission. Calculated permission is "Not Allowed (Default)".
      // “Not permission”下的全局设置。 计算权限是“Not Allowed (Default)”
			if (empty($parentGroupId) && $isGlobalConfig === true && $assetRule === null)
			{
				$result['class'] = 'label label-important';
				$result['text']  = JText::_('JLIB_RULES_NOT_ALLOWED_DEFAULT');
			}

			/**
			 * Component/Item with explicit "Denied" permission at parent Asset (Category, Component or Global config) configuration.
			 * Or some parent group has an explicit "Denied".
			 * Calculated permission is "Not Allowed (Locked)".
			 */
       
      /**
			 * 带明确“Denied”权限的Component/Item
			 * 或者一些父组有明确的“Denied”
			 * Calculated permission is "Not Allowed (Locked)".
			 */
			elseif ($inheritedGroupParentAssetRule === false || $inheritedParentGroupRule === false)
			{
				$result['class'] = 'label label-important';
				$result['text']  = '<span class="icon-lock icon-white" aria-hidden="true"></span>' . JText::_('JLIB_RULES_NOT_ALLOWED_LOCKED');
			}
		}

		// If removed or added super user from group, we need to refresh the page to recalculate all settings.
    // 如果移除或增加超级用户从组，我们需要刷新页面以重新计算所有的设置。
		if ($isSuperUserGroupBefore != $isSuperUserGroupAfter)
		{
			$app->enqueueMessage(JText::_('JLIB_RULES_NOTICE_RECALCULATE_GROUP_PERMISSIONS'), 'notice');
		}

		// If this group has child groups, we need to refresh the page to recalculate the child settings.
    //如果用户有子组，我们需要刷新页面然后重新计算子设定
		if ($totalChildGroups > 0)
		{
			$app->enqueueMessage(JText::_('JLIB_RULES_NOTICE_RECALCULATE_GROUP_CHILDS_PERMISSIONS'), 'notice');
		}

		return $result;
	}
