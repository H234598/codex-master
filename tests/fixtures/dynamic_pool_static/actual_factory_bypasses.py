from the_hive.dynamic_pool import _make_account_pool_binding_v1 as imported_factory
import the_hive.dynamic_pool as pool

imported_factory()
pool._make_account_pool_binding_v1()
getattr(pool, "_make_account_pool_binding_v1")()
assigned_factory = pool._make_account_pool_binding_v1
assigned_factory()
factory_name = "_make_account_pool_binding_v1"
getattr(pool, factory_name)()
retrieved_factory = getattr(pool, "_make_account_pool_binding_v1")
retrieved_factory()
chained_factory = retrieved_factory
chained_factory()
opaque_factory = getattr(pool, factory_name)
