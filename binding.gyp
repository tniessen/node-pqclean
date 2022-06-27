{
  "targets": [
    {
      "target_name": "node_pqclean",
      "sources": ["native/node_pqclean.cc"],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "<(module_root_dir)/deps/PQClean"
      ],
      "dependencies": [
        "<!(node -p \"require('node-addon-api').gyp\")",
        "<(module_root_dir)/native/gen/binding.gyp:pqclean"
      ],
      "defines": [
        "NAPI_DISABLE_CPP_EXCEPTIONS",
        "NODE_ADDON_API_DISABLE_DEPRECATED"
      ]
    }
  ]
}
