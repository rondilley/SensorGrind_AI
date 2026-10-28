// sg.akd._akd: a Python 3.14 binding of BrainChip libakida.so.2.
//
// The akida wheels on PyPI have a pybind11 module for CPython 3.10..3.12
// only.  libakida.so.2 is plain C++ (no CPython symbols) and the wheel ships
// its public headers (akida/api, akida/engine/api), so this file binds the
// part of that API the AKD1500 bench uses: layers, models, variables,
// mapping, forward/predict/fit, virtual and hardware devices.
//
// Build: python src/sg/akd/build.py (downloads the pinned wheel, checks its
// sha256, compiles this file against it).

#include <pybind11/numpy.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <cstring>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "akida/dense.h"
#include "akida/device.h"
#include "akida/hw_version.h"
#include "akida/layer.h"
#include "akida/layer_params.h"
#include "akida/learning_params.h"
#include "akida/mesh.h"
#include "akida/model.h"
#include "akida/np.h"
#include "akida/sequence.h"
#include "akida/version.h"
#include "host/hardware_devices.h"

namespace py = pybind11;
using namespace akida;

namespace {

// A Device with no hardware: the mapper only needs the version and the mesh.
// This is what akida.virtual_devices builds in the BrainChip Python layer.
class VirtualDevice final : public Device {
 public:
  VirtualDevice(HwVersion version, Mesh mesh)
      : version_(version), mesh_(std::move(mesh)), desc_(version.to_string()) {}
  HwVersion version() const override { return version_; }
  const char* desc() const override { return desc_.c_str(); }
  const Mesh& mesh() const override { return mesh_; }
  HardwareDevice* hardware() const override { return nullptr; }

 private:
  HwVersion version_;
  Mesh mesh_;
  std::string desc_;
};

TensorType tensor_type_of(const py::dtype& dt) {
  if (dt.is(py::dtype::of<uint8_t>())) return TensorType::uint8;
  if (dt.is(py::dtype::of<int8_t>())) return TensorType::int8;
  if (dt.is(py::dtype::of<int16_t>())) return TensorType::int16;
  if (dt.is(py::dtype::of<uint16_t>())) return TensorType::uint16;
  if (dt.is(py::dtype::of<int32_t>())) return TensorType::int32;
  if (dt.is(py::dtype::of<float>())) return TensorType::float32;
  throw std::invalid_argument("unsupported dtype " +
                              std::string(py::str(dt)));
}

// numpy dtype that holds a TensorType (sub-byte types use one byte each)
py::dtype dtype_of(TensorType t) {
  switch (t) {
    case TensorType::uint8:
    case TensorType::uint4:
    case TensorType::uint2:
    case TensorType::bit:
      return py::dtype::of<uint8_t>();
    case TensorType::int8:
    case TensorType::int4:
    case TensorType::int2:
      return py::dtype::of<int8_t>();
    case TensorType::int16:
      return py::dtype::of<int16_t>();
    case TensorType::uint16:
      return py::dtype::of<uint16_t>();
    case TensorType::int32:
      return py::dtype::of<int32_t>();
    case TensorType::float32:
      return py::dtype::of<float>();
  }
  throw std::invalid_argument("unknown tensor type");
}

Shape shape_of(const py::array& a) {
  if (a.ndim() < 1 || a.ndim() > 4) {
    throw std::invalid_argument("akida tensors have 1 to 4 dimensions");
  }
  std::vector<Index> dims(a.shape(), a.shape() + a.ndim());
  return Shape(dims);
}

// Copy a numpy array into a Dense of type t and the given layout.
DenseConstPtr to_dense(const py::array& in, TensorType t,
                       Dense::Layout layout = Dense::Layout::RowMajor) {
  py::array a = layout == Dense::Layout::RowMajor
                    ? py::array::ensure(in, py::array::c_style)
                    : py::array::ensure(in, py::array::f_style);
  if (!a) throw std::invalid_argument("cannot read the array");
  py::dtype want = dtype_of(t);
  if (!a.dtype().is(want)) {
    a = a.attr("astype")(want, py::arg("order") =
                                   layout == Dense::Layout::RowMajor ? "C" : "F");
  }
  return Dense::copy(static_cast<const char*>(a.data()), a.nbytes(), t,
                     shape_of(a), layout);
}

// Copy a Dense (either layout) into a new C-ordered numpy array.
py::array to_numpy(const Tensor& tensor) {
  auto dense = Tensor::ensure_dense(
      std::shared_ptr<const Tensor>(&tensor, [](const Tensor*) {}));
  py::dtype dt = dtype_of(dense->type());
  const Shape dims = dense->dimensions();
  std::vector<py::ssize_t> shape(dims.begin(), dims.end());
  std::vector<py::ssize_t> strides;
  for (auto s : dense->strides()) strides.push_back(s * dt.itemsize());
  py::array view(dt, shape, strides, dense->buffer()->data());
  return view.attr("copy")("C");
}

LayerParams::Dict to_dict(const py::dict& d) {
  LayerParams::Dict out;
  for (auto item : d) {
    out.emplace(py::cast<std::string>(item.first),
                py::cast<LayerParams::Value>(item.second));
  }
  return out;
}

py::dict params_dict(const LayerParams* p) {
  py::dict d;
  for (const auto& k : p->keys()) d[py::str(k)] = p->get(k);
  return d;
}

py::list components(const Layer& layer) {
  py::list out;
  auto m = layer.mapping();
  if (!m || !m->components) return out;
  for (const auto& c : *m->components) {
    py::dict d;
    d["type"] = hw::to_string(c.type);
    d["ident"] = py::make_tuple(c.id.col, c.id.row, c.id.id);
    if (c.np) {
      d["start_neuron"] = c.np->start_neuron;
      d["neurons"] = c.np->num_neurons;
    }
    d["input_bytes"] = c.mem_info.input_size;
    d["weight_bytes"] = c.mem_info.weight_size;
    d["external_bytes"] = c.mem_info.external_size;
    out.append(d);
  }
  return out;
}

}  // namespace

PYBIND11_MODULE(_akd, m) {
  m.doc() = "Python 3.14 binding of BrainChip libakida (subset)";
  m.attr("__version__") = version();

  py::enum_<LayerType>(m, "LayerType")
      .value("InputData", LayerType::InputData)
      .value("InputConvolutional", LayerType::InputConvolutional)
      .value("FullyConnected", LayerType::FullyConnected)
      .value("Convolutional", LayerType::Convolutional)
      .value("SeparableConvolutional", LayerType::SeparableConvolutional);
  py::enum_<IpVersion>(m, "IpVersion")
      .value("none", IpVersion::none)
      .value("v1", IpVersion::v1)
      .value("v2", IpVersion::v2)
      .value("pico", IpVersion::pico);
  py::enum_<hw::Type>(m, "NpType")
      .value("HRC", hw::Type::HRC)
      .value("CNP1", hw::Type::CNP1)
      .value("CNP2", hw::Type::CNP2)
      .value("FNP2", hw::Type::FNP2)
      .value("FNP3", hw::Type::FNP3);
  py::enum_<BackendType>(m, "BackendType")
      .value("Software", BackendType::Software)
      .value("Hardware", BackendType::Hardware)
      .value("Hybrid", BackendType::Hybrid);

  py::class_<HwVersion>(m, "HwVersion")
      .def(py::init<uint8_t, uint8_t, uint8_t, uint8_t>(), py::arg("vendor_id"),
           py::arg("product_id"), py::arg("major_rev"), py::arg("minor_rev"))
      .def_readonly("vendor_id", &HwVersion::vendor_id)
      .def_readonly("product_id", &HwVersion::product_id)
      .def_readonly("major_rev", &HwVersion::major_rev)
      .def_readonly("minor_rev", &HwVersion::minor_rev)
      .def_property_readonly("ip_version", &HwVersion::get_ip_version)
      .def("__eq__", &HwVersion::operator==)
      .def("__repr__", &HwVersion::to_string);
  m.attr("NSoC_v2") = NSoC_v2;
  m.attr("TwoNodesIP_v1") = TwoNodesIP_v1;
  m.attr("AKD1500_v1") = AKD1500_v1;

  py::class_<hw::Ident>(m, "Ident")
      .def(py::init([](uint8_t col, uint8_t row, uint8_t id) {
             return hw::Ident{col, row, id};
           }),
           py::arg("col"), py::arg("row"), py::arg("id"))
      .def_readonly("col", &hw::Ident::col)
      .def_readonly("row", &hw::Ident::row)
      .def_readonly("id", &hw::Ident::id);

  py::class_<np::Info>(m, "NpInfo")
      .def(py::init([](hw::Ident ident, std::set<hw::Type> types, bool lut) {
             return np::Info{ident, types, lut};
           }),
           py::arg("ident"), py::arg("types"), py::arg("has_lut") = false)
      .def_static("hrc", &np::Info::hrc, py::arg("has_lut") = false)
      .def_readonly("ident", &np::Info::ident)
      .def_readonly("types", &np::Info::types);

  py::class_<Mesh>(m, "Mesh")
      .def(py::init<IpVersion, const hw::Ident&, const hw::Ident&,
                    std::optional<np::Info>, std::vector<np::Info>,
                    std::vector<np::Info>>(),
           py::arg("version"), py::arg("dma_event"), py::arg("dma_conf"),
           py::arg("hrc"), py::arg("nps"),
           py::arg("skip_dmas") = std::vector<np::Info>{})
      .def_readonly("version", &Mesh::version)
      .def_readonly("nps", &Mesh::nps);

  py::class_<Device, DevicePtr>(m, "Device")
      .def_property_readonly("version", &Device::version)
      .def_property_readonly("desc", &Device::desc)
      .def_property_readonly("mesh", &Device::mesh,
                             py::return_value_policy::reference_internal)
      .def_property_readonly("is_hardware", [](const Device& d) {
        return d.hardware() != nullptr;
      });
  m.def(
      "virtual_device",
      [](HwVersion v, const Mesh& mesh) -> DevicePtr {
        return std::make_shared<VirtualDevice>(v, mesh);
      },
      py::arg("version"), py::arg("mesh"));
  m.def(
      "devices", []() { return get_devices(); },
      "hardware devices found by the driver (empty with no card)");

  py::class_<Layer, LayerPtr>(m, "Layer")
      .def(py::init([](LayerType type, const py::dict& params,
                       const std::string& name) {
             auto p = LayerParams::create(type, to_dict(params));
             return Layer::create(p.get(), name);
           }),
           py::arg("type"), py::arg("params"), py::arg("name") = "")
      .def_property("name", &Layer::get_name, &Layer::set_name)
      .def_property_readonly("params",
                             [](const Layer& l) { return params_dict(l.params()); })
      .def_property_readonly(
          "layer_type", [](const Layer& l) { return l.params()->layer_type(); })
      .def_property_readonly("input_dims",
                             [](const Layer& l) {
                               std::vector<std::vector<Index>> out;
                               for (const auto& s : l.input_dimensions())
                                 out.emplace_back(s.begin(), s.end());
                               return out;
                             })
      .def_property_readonly("output_dims",
                             [](const Layer& l) {
                               auto s = l.output_dimensions();
                               return std::vector<Index>(s.begin(), s.end());
                             })
      .def_property_readonly("input_bits", &Layer::input_bits)
      .def_property_readonly("output_bits", &Layer::output_bits)
      .def_property_readonly("output_signed", &Layer::output_signed)
      .def_property_readonly("macs", &Layer::get_macs)
      .def_property_readonly("variable_names",
                             [](const Layer& l) { return l.variables().names(); })
      .def(
          "get_variable",
          [](const Layer& l, const std::string& name) {
            return to_numpy(*l.variables().get(name));
          },
          py::arg("name"))
      .def(
          "variable_type",
          [](const Layer& l, const std::string& name) {
            return std::string(Tensor::type_name(l.variables().get(name)->type()));
          },
          py::arg("name"))
      .def(
          "set_variable",
          [](Layer& l, const std::string& name, const py::array& values) {
            // keep the type (int4, uint4, int8 ...) and the layout that
            // libakida chose for this variable
            auto cur = Tensor::ensure_dense(std::as_const(l).variables().get(name));
            l.variables()->set(name, to_dense(values, cur->type(), cur->layout()));
          },
          py::arg("name"), py::arg("values"))
      .def_property_readonly("mapping", &components);

  py::class_<Sequence, SequencePtr>(m, "Sequence")
      .def_property_readonly("name", &Sequence::name)
      .def_property_readonly("backend", &Sequence::backend)
      .def_property_readonly(
          "program_bytes",
          [](const Sequence& s) { return s.program().size; })
      .def_property_readonly("passes", [](const Sequence& s) {
        std::vector<std::vector<std::string>> out;
        for (const auto& p : s.passes()) {
          std::vector<std::string> names;
          for (const auto& l : p->layers) names.push_back(l->get_name());
          out.push_back(names);
        }
        return out;
      });

  py::class_<Model>(m, "Model")
      .def(py::init(&Model::create))
      .def_static(
          "from_bytes",
          [](const py::bytes& b) {
            std::string s = b;
            return Model::from_buffer(s.data(), s.size());
          },
          py::arg("data"))
      .def("to_bytes",
           [](Model& self) {
             auto v = self.to_buffer();
             return py::bytes(v.data(), v.size());
           })
      .def(
          "add",
          [](Model& self, LayerPtr layer, std::vector<LayerPtr> inbound) {
            self.add(layer, inbound);
          },
          py::arg("layer"), py::arg("inbound_layers") = std::vector<LayerPtr>{})
      .def("pop_layer", &Model::pop_layer)
      .def_property_readonly("layers", &Model::get_layers)
      .def("get_layer",
           py::overload_cast<const std::string&>(&Model::get_layer),
           py::arg("name"))
      .def_property_readonly("input_shape",
                             [](const Model& self) {
                               auto s = self.input_shape();
                               return std::vector<Index>(s.begin(), s.end());
                             })
      .def_property_readonly("output_shape",
                             [](const Model& self) {
                               auto s = self.output_shape();
                               return std::vector<Index>(s.begin(), s.end());
                             })
      .def_property_readonly("input_signed", &Model::input_signed)
      .def_property_readonly("macs", &Model::get_macs)
      .def_property_readonly("ip_version", &Model::get_ip_version)
      .def(
          "map",
          [](Model& self, DevicePtr device, bool hw_only) {
            py::gil_scoped_release nogil;
            self.map(device, hw_only);
          },
          py::arg("device"), py::arg("hw_only") = false)
      .def_property_readonly("sequences", &Model::sequences)
      .def_property_readonly("device", &Model::device)
      .def(
          "forward",
          [](Model& self, const py::array& x, uint32_t batch_size) {
            auto in = to_dense(x, tensor_type_of(x.dtype()));
            DensePtr out;
            {
              py::gil_scoped_release nogil;
              out = self.forward(in, batch_size);
            }
            return to_numpy(*out);
          },
          py::arg("inputs"), py::arg("batch_size") = 0)
      .def(
          "predict",
          [](Model& self, const py::array& x, uint32_t batch_size) {
            auto in = to_dense(x, tensor_type_of(x.dtype()));
            DensePtr out;
            {
              py::gil_scoped_release nogil;
              out = self.predict(in, batch_size);
            }
            return to_numpy(*out);
          },
          py::arg("inputs"), py::arg("batch_size") = 0)
      .def(
          "compile",
          [](Model& self, const std::map<std::string, double>& params) {
            LearningParams::Dict d(params.begin(), params.end());
            self.compile(*LearningParams::create(
                LearningType::AkidaUnsupervised, d));
          },
          py::arg("params"),
          "set the edge-learning parameters of the last layer "
          "(AkidaUnsupervised: num_weights, num_classes, learning_competition, "
          "initial_plasticity, min_plasticity, plasticity_decay)")
      .def(
          "fit",
          [](Model& self, const py::array& x, std::vector<int32_t> labels,
             uint32_t batch_size) {
            auto in = to_dense(x, tensor_type_of(x.dtype()));
            DensePtr out;
            {
              py::gil_scoped_release nogil;
              out = self.fit(in, labels, batch_size);
            }
            return to_numpy(*out);
          },
          py::arg("inputs"), py::arg("labels") = std::vector<int32_t>{},
          py::arg("batch_size") = 0);
}
