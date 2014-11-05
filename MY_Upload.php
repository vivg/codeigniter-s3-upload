<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');
class MY_Upload extends CI_Upload {

	public $bucket_name = '';
	public $acl = '';
	
	/**
	 * Constructor
	 *
	 * @access	public
	 */
	public function __construct($props = array())
	{
		parent::__construct($props);
		$this->bucket_name = empty($props['bucket_name'])?'':$props['bucket_name'];
		$this->acl = empty($props['acl'])?'public-read':$props['acl'];
	}
	
	
	// --------------------------------------------------------------------

	/**
	 * Perform s3 file upload
	 *
	 * @return	bool
	 */
	public function do_upload_s3($field = 'userfile')
	{
		// Is $_FILES[$field] set? If not, no reason to continue.
		if ( ! isset($_FILES[$field]))
		{
			$this->set_error('upload_no_file_selected');
			return FALSE;
		}

		// Was the file able to be uploaded? If not, determine the reason why.
		if ( ! is_uploaded_file($_FILES[$field]['tmp_name']))
		{
			$error = ( ! isset($_FILES[$field]['error'])) ? 4 : $_FILES[$field]['error'];

			switch($error)
			{
				case 1:	// UPLOAD_ERR_INI_SIZE
					$this->set_error('upload_file_exceeds_limit');
					break;
				case 2: // UPLOAD_ERR_FORM_SIZE
					$this->set_error('upload_file_exceeds_form_limit');
					break;
				case 3: // UPLOAD_ERR_PARTIAL
					$this->set_error('upload_file_partial');
					break;
				case 4: // UPLOAD_ERR_NO_FILE
					$this->set_error('upload_no_file_selected');
					break;
				case 6: // UPLOAD_ERR_NO_TMP_DIR
					$this->set_error('upload_no_temp_directory');
					break;
				case 7: // UPLOAD_ERR_CANT_WRITE
					$this->set_error('upload_unable_to_write_file');
					break;
				case 8: // UPLOAD_ERR_EXTENSION
					$this->set_error('upload_stopped_by_extension');
					break;
				default :   $this->set_error('upload_no_file_selected');
					break;
			}

			return FALSE;
		}


		// Set the uploaded data as class variables
		$this->file_temp = $_FILES[$field]['tmp_name'];
		$this->file_size = $_FILES[$field]['size'];
		$this->_file_mime_type($_FILES[$field]);
		$this->file_type = preg_replace("/^(.+?);.*$/", "\\1", $this->file_type);
		$this->file_type = strtolower(trim(stripslashes($this->file_type), '"'));
		$this->file_name = $this->_prep_filename($_FILES[$field]['name']);
		$this->file_ext	 = $this->get_extension($this->file_name);
		$this->client_name = $this->file_name;

		// Is the file type allowed to be uploaded?
		if ( ! $this->is_allowed_filetype())
		{
			$this->set_error('upload_invalid_filetype');
			return FALSE;
		}

		// if we're overriding, let's now make sure the new name and type is allowed
		if ($this->_file_name_override != '')
		{
			$this->file_name = $this->_prep_filename($this->_file_name_override);

			// If no extension was provided in the file_name config item, use the uploaded one
			if (strpos($this->_file_name_override, '.') === FALSE)
			{
				$this->file_name .= $this->file_ext;
			}

			// An extension was provided, lets have it!
			else
			{
				$this->file_ext	 = $this->get_extension($this->_file_name_override);
			}

			if ( ! $this->is_allowed_filetype(TRUE))
			{
				$this->set_error('upload_invalid_filetype');
				return FALSE;
			}
		}

		// Convert the file size to kilobytes
		if ($this->file_size > 0)
		{
			$this->file_size = round($this->file_size/1024, 2);
		}

		// Is the file size within the allowed maximum?
		if ( ! $this->is_allowed_filesize())
		{
			$this->set_error('upload_invalid_filesize');
			return FALSE;
		}

		// Are the image dimensions within the allowed size?
		// Note: This can fail if the server has an open_basdir restriction.
		if ( ! $this->is_allowed_dimensions())
		{
			$this->set_error('upload_invalid_dimensions');
			return FALSE;
		}

		// Sanitize the file name for security
		$this->file_name = $this->clean_file_name($this->file_name);

		// Truncate the file name if it's too long
		if ($this->max_filename > 0)
		{
			$this->file_name = $this->limit_filename_length($this->file_name, $this->max_filename);
		}

		// Remove white spaces in the name
		if ($this->remove_spaces == TRUE)
		{
			$this->file_name = preg_replace("/\s+/", "_", $this->file_name);
		}

		/*
		 * Validate the file name
		 * This function appends an number onto the end of
		 * the file if one with the same name already exists.
		 * If it returns false there was a problem.
		 */
		$this->orig_name = $this->file_name;
		
		//trim upload path's trailing slash
		$this->upload_path = rtrim($this->upload_path, "/");

		if ($this->overwrite == FALSE)
		{
			$this->file_name = $this->set_filename_s3($this->upload_path, $this->bucket_name, $this->file_name);

			if ($this->file_name === FALSE)
			{
				return FALSE;
			}
		}

		/*
		 * Run the file through the XSS hacking filter
		 * This helps prevent malicious code from being
		 * embedded within a file.  Scripts can easily
		 * be disguised as images or other file types.
		 */
		if ($this->xss_clean)
		{
			if ($this->do_xss_clean() === FALSE)
			{
				$this->set_error('upload_unable_to_write_file');
				return FALSE;
			}
		}

		/*
		 * Move the file to the s3
		 */
		 
		$CI =& get_instance();
		$CI->load->library('s3');
		
		$upload_file = $CI->s3->inputFile($this->file_temp, false);
		
		if(! $CI->s3->putObject($upload_file, $this->upload_path, $this->bucket_name . "/" . $this->file_name, $this->acl, array(),array('Content-Type' => $this->file_type))) {
			$this->set_error('upload_destination_error');
			return FALSE;
		}

		return TRUE;
	}
	
	// --------------------------------------------------------------------

	/**
	 * Set s3 file name
	 *
	 * This function takes a filename/path as input and looks for the
	 * existence of a file with the same name. If found, it will append a
	 * number to the end of the filename to avoid overwriting a pre-existing file.
	 *
	 * @param	string
	 * @param	string
	 * @return	string
	 */
	public function set_filename_s3($path, $bucketname, $filename)
	{
		$CI =& get_instance();
		$CI->load->library('s3');
		
		if ($this->encrypt_name == TRUE)
		{
			mt_srand();
			$filename = md5(uniqid(mt_rand())).$this->file_ext;
		}

		if ( ! $CI->s3->getObjectInfo($path, $bucketname . "/" . $filename))
		{
			return $filename;
		}

		$filename = str_replace($this->file_ext, '', $filename);

		$new_filename = '';
		for ($i = 1; $i < 100; $i++)
		{
			if ( ! $CI->s3->getObjectInfo($path, $bucketname . "/" . $filename.$i.$this->file_ext))
			{
				$new_filename = $filename.$i.$this->file_ext;
				break;
			}
		}

		if ($new_filename == '')
		{
			$this->set_error('upload_bad_filename');
			return FALSE;
		}
		else
		{
			return $new_filename;
		}
	}
	
	// --------------------------------------------------------------------

	/**
	 * Finalized Data Array
	 *
	 * Returns an associative array containing all of the information
	 * related to the upload, allowing the developer easy access in one array.
	 *
	 * @return	array
	 */
	public function data_s3()
	{
		return array (
						'file_name'				=> $this->file_name,
						'file_type'				=> $this->file_type,
						'file_path'				=> $this->upload_path . "/" . $this->bucket_name . "/",
						'full_path'				=> $this->upload_path . "/" . $this->bucket_name . "/" . $this->file_name,
						'raw_name'				=> str_replace($this->file_ext, '', $this->file_name),
						'orig_name'				=> $this->orig_name,
						'client_name'			=> $this->client_name,
						'file_ext'				=> $this->file_ext,
						'file_size'				=> $this->file_size,
						'is_image'				=> $this->is_image(),
						'image_width'			=> $this->image_width,
						'image_height'			=> $this->image_height,
						'image_type'			=> $this->image_type,
						'image_size_str'		=> $this->image_size_str,
					);
	}

}
