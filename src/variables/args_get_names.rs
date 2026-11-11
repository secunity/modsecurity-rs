//! Port of `src/variables/args_get_names.h`.
//!
//! `DEFINE_VARIABLE_DICT(ArgsGetNames, ARGS_GET_NAMES, m_variableArgsGetNames)`

define_variable_dict_proxy!(ArgsGetNames, "ARGS_GET_NAMES", args_get_names, args_get);
