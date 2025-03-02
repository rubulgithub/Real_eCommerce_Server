import { Category } from "../models/category.models.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { getMongoosePaginationOptions } from "../utils/helpers.js";

const getCategoryById = asyncHandler(async (req, res) => {
  const { categoryId } = req.params;
  const category = await Category.findById(categoryId);
  if (!category) {
    throw new ApiError(404, "Category does not exist");
  }
  return res
    .status(200)
    .json(new ApiResponse(200, category, "Category fetched successfully"));
});

const updateCategory = asyncHandler(async (req, res) => {
  const { categoryId } = req.params;
  const { name } = req.body;
  const category = await Category.findByIdAndUpdate(
    categoryId,
    {
      $set: {
        name,
      },
    },
    { new: true }
  );
  if (!category) {
    throw new ApiError(404, "Category does not exist");
  }

  return res
    .status(200)
    .json(new ApiResponse(200, category, "Category updated successfully"));
});

const createCategory = asyncHandler(async (req, res) => {
  const { name, parent, isCulturalState } = req.body;

  // Validate parent category if provided
  if (parent) {
    const parentCategory = await Category.findById(parent);
    if (!parentCategory) {
      throw new ApiError(400, "Parent category does not exist");
    }
  }

  const category = await Category.create({
    name,
    owner: req.user._id,
    parent: parent || null,
    isCulturalState: Boolean(isCulturalState),
  });

  return res
    .status(201)
    .json(new ApiResponse(200, category, "Category created successfully"));
});

const getCategoryTree = asyncHandler(async (req, res) => {
  const buildTree = async (parentId = null) => {
    const categories = await Category.find({ parent: parentId });
    return Promise.all(
      categories.map(async (category) => ({
        ...category.toObject(),
        children: await buildTree(category._id),
      }))
    );
  };

  const tree = await buildTree();
  return res
    .status(200)
    .json(new ApiResponse(200, tree, "Category tree fetched successfully"));
});

const getAllCategories = asyncHandler(async (req, res) => {
  const { page = 1, limit = 10, flatten } = req.query;

  const pipeline = [];

  if (flatten === "true") {
    // For flat list with parent info
    pipeline.push({
      $lookup: {
        from: "categories",
        localField: "parent",
        foreignField: "_id",
        as: "parent",
      },
    });
    pipeline.push({
      $unwind: { path: "$parent", preserveNullAndEmptyArrays: true },
    });
  }

  const categoryAggregate = Category.aggregate(pipeline);

  const categories = await Category.aggregatePaginate(
    categoryAggregate,
    getMongoosePaginationOptions({
      page,
      limit,
      customLabels: {
        totalDocs: "totalCategories",
        docs: "categories",
      },
    })
  );

  return res
    .status(200)
    .json(new ApiResponse(200, categories, "Categories fetched successfully"));
});

const deleteCategory = asyncHandler(async (req, res) => {
  const { categoryId } = req.params;

  // Check for child categories
  const childCategories = await Category.find({ parent: categoryId });
  if (childCategories.length > 0) {
    throw new ApiError(400, "Cannot delete category with child categories");
  }

  const category = await Category.findByIdAndDelete(categoryId);
  if (!category) {
    throw new ApiError(404, "Category does not exist");
  }

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        { deletedCategory: category },
        "Category deleted successfully"
      )
    );
});

// Updated export
export {
  createCategory,
  getAllCategories,
  getCategoryById,
  updateCategory,
  deleteCategory,
  getCategoryTree,
};
