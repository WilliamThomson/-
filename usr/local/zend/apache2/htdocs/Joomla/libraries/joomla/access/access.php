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
  /**
	 * 检查组是否被认证以执行动作，通常对asset
	 *
	 * @param   integer         $groupId   认证组的路径
	 * @param   string          $action    action的名字
	 * @param   integer|string  $assetKey  The asset key (asset id or asset name). null fallback to root asset.
	 * @param   boolean         $preload   是否预加载
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
