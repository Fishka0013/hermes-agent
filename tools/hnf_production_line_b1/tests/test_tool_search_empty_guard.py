from unittest.mock import patch


def _minimal_tool_def(name="terminal"):
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": "synthetic tool",
            "parameters": {"type": "object", "properties": {}},
        },
    }


class TestToolSearchAssemblyContextGuard:
    def test_empty_tools_skip_context_and_provider_resolution(self):
        import model_tools
        from agent import model_metadata
        from tools import tool_search

        cfg = tool_search.ToolSearchConfig.from_raw({"enabled": "on"})
        with patch.object(model_tools, "_select_tool_names", return_value=set()), \
             patch.object(model_tools.registry, "get_definitions", return_value=[]), \
             patch.object(tool_search, "load_config", return_value=cfg), \
             patch.object(model_tools, "_resolve_active_context_length") as mock_ctx, \
             patch("hermes_cli.runtime_provider.resolve_runtime_provider") as mock_runtime, \
             patch.object(model_metadata, "get_model_context_length") as mock_metadata, \
             patch.object(model_metadata.model_metadata_http, "get") as mock_catalog:
            result = model_tools._compute_tool_definitions(enabled_toolsets=[], quiet_mode=True)

        assert result == []
        mock_ctx.assert_not_called()
        mock_runtime.assert_not_called()
        mock_metadata.assert_not_called()
        mock_catalog.assert_not_called()

    def test_nonempty_tools_preserve_context_sizing(self):
        import model_tools
        from types import SimpleNamespace
        from tools import tool_search

        tool_def = _minimal_tool_def()
        cfg = tool_search.ToolSearchConfig.from_raw({"enabled": "on"})
        assembled = SimpleNamespace(tool_defs=[tool_def], activated=False, tier=0, deferred_count=0, deferred_tokens=0, listing_form="none")
        with patch.object(model_tools, "_select_tool_names", return_value={"terminal"}), \
             patch.object(model_tools.registry, "get_definitions", return_value=[tool_def]), \
             patch.object(tool_search, "load_config", return_value=cfg), \
             patch.object(model_tools, "_resolve_active_context_length", return_value=272000) as mock_ctx, \
             patch.object(tool_search, "assemble_tool_defs", return_value=assembled) as mock_assemble:
            result = model_tools._compute_tool_definitions(enabled_toolsets=["terminal"], quiet_mode=True)

        assert result == [tool_def]
        mock_ctx.assert_called_once_with()
        assert mock_assemble.call_args.kwargs["context_length"] == 272000

    def test_tool_search_disabled_preserves_no_assembly_behavior(self):
        import model_tools
        from tools import tool_search

        tool_def = _minimal_tool_def()
        cfg = tool_search.ToolSearchConfig.from_raw({"enabled": "off"})
        with patch.object(model_tools, "_select_tool_names", return_value={"terminal"}), \
             patch.object(model_tools.registry, "get_definitions", return_value=[tool_def]), \
             patch.object(tool_search, "load_config", return_value=cfg), \
             patch.object(model_tools, "_resolve_active_context_length") as mock_ctx, \
             patch.object(tool_search, "assemble_tool_defs") as mock_assemble:
            result = model_tools._compute_tool_definitions(enabled_toolsets=["terminal"], quiet_mode=True)

        assert [td["function"]["name"] for td in result] == ["terminal"]
        mock_ctx.assert_not_called()
        mock_assemble.assert_not_called()

    def test_explicit_skip_tool_search_assembly_preserved(self):
        import model_tools
        from tools import tool_search

        tool_def = _minimal_tool_def()
        cfg = tool_search.ToolSearchConfig.from_raw({"enabled": "on"})
        with patch.object(model_tools, "_select_tool_names", return_value={"terminal"}), \
             patch.object(model_tools.registry, "get_definitions", return_value=[tool_def]), \
             patch.object(tool_search, "load_config", return_value=cfg), \
             patch.object(model_tools, "_resolve_active_context_length") as mock_ctx, \
             patch.object(tool_search, "assemble_tool_defs") as mock_assemble:
            result = model_tools._compute_tool_definitions(enabled_toolsets=["terminal"], quiet_mode=True, skip_tool_search_assembly=True)

        assert [td["function"]["name"] for td in result] == ["terminal"]
        mock_ctx.assert_not_called()
        mock_assemble.assert_not_called()
